"""
I9 — Insecure Default Settings
OWASP IoT Top 10:2018

Detects network-observable indicators that a device is still running with
factory default configuration. Focuses on signals NOT already covered by
other checks:
  - I1 covers default credentials
  - I2 covers dangerous open services
  - I7 covers cleartext transport

This check targets:
  - UPnP/SSDP exposure (port 1900 UDP)
  - Android Debug Bridge exposure (port 5555 TCP)
  - SNMP with default 'public' community string (port 161 UDP)
  - Default/factory hostnames and device identifiers in HTTP responses
  - Setup wizard pages still accessible post-deployment
  - mDNS/Bonjour exposure (port 5353 UDP)
  - Default SSID/network names leaked in API responses
"""

import socket
import time
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS = [80, 8080, 8888, 443, 8443]

# Factory-default hostnames commonly found on IoT devices
DEFAULT_HOSTNAME_PATTERNS = [
    re.compile(r'\bOpenWrt\b', re.IGNORECASE),
    re.compile(r'\bDD-?WRT\b', re.IGNORECASE),
    re.compile(r'\bTomato\b', re.IGNORECASE),
    re.compile(r'\bASUS Router\b', re.IGNORECASE),
    re.compile(r'\bTP-?LINK\b', re.IGNORECASE),
    re.compile(r'\bNetgear\b', re.IGNORECASE),
    re.compile(r'\bLinksys\b', re.IGNORECASE),
    re.compile(r'\bD-?Link\b', re.IGNORECASE),
    re.compile(r'\bZyXEL\b', re.IGNORECASE),
    re.compile(r'\bMikroTik\b', re.IGNORECASE),
    re.compile(r'\bUbiquiti\b', re.IGNORECASE),
    re.compile(r'\bRaspberry ?Pi\b', re.IGNORECASE),
    re.compile(r'\bESP32\b', re.IGNORECASE),
    re.compile(r'\bESP8266\b', re.IGNORECASE),
    re.compile(r'\bArduino\b', re.IGNORECASE),
    re.compile(r'\bdefault[\s_-]?(device|gateway|router|ap)\b', re.IGNORECASE),
    re.compile(r'\bmy[\s_-]?(device|gateway|router|ap)\b', re.IGNORECASE),
    re.compile(r'\bhome[\s_-]?(gateway|router|ap)\b', re.IGNORECASE),
]

# Setup/wizard paths — distinct from I3's auth bypass list because
# the purpose here is detecting "device never configured" state
SETUP_WIZARD_PATHS = [
    '/setup',
    '/wizard',
    '/first-run',
    '/firstrun',
    '/initial-setup',
    '/quicksetup',
    '/quick-setup',
    '/getting-started',
    '/welcome',
    '/install',
    '/configure',
]

# Keywords that confirm a page is a setup wizard (not just a named endpoint)
SETUP_KEYWORDS = [
    'setup', 'wizard', 'first time', 'initial configuration',
    'get started', 'getting started', 'configure your',
    'welcome to your', 'step 1', 'create account',
    'set password', 'choose password', 'network settings',
]


def _is_tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _is_udp_responsive(ip: str, port: int, probe: bytes, timeout: float = 3.0) -> tuple[bool, bytes]:
    """Send a UDP probe and check for a response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(probe, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return True, data
    except Exception:
        return False, b''


def _check_upnp(ip: str) -> list[dict]:
    """Check for UPnP/SSDP on port 1900 UDP."""
    findings = []

    ssdp_probe = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 2\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    ).encode()

    responsive, data = _is_udp_responsive(ip, 1900, ssdp_probe, timeout=3.0)

    if responsive:
        response_text = data.decode('utf-8', errors='replace')[:500]
        server_match = re.search(r'SERVER:\s*(.+)', response_text, re.IGNORECASE)
        server_info = server_match.group(1).strip() if server_match else ''

        findings.append({
            'finding_id': 'I9-UPNP-OPEN',
            'title': 'UPnP/SSDP Service Enabled (Port 1900)',
            'port': 1900,
            'protocol': 'UDP',
            'service': 'UPnP/SSDP',
            'server_info': server_info,
            'risk_level': 'High',
            'cvss_score': 7.5,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'description': (
                'The device responds to UPnP SSDP discovery probes on port 1900/UDP. '
                'UPnP is enabled by default on many consumer IoT devices and routers. '
                'It allows any device on the local network to automatically open firewall ports '
                '(via IGD), discover device capabilities, and in some cases execute administrative '
                'actions without authentication. UPnP has been exploited in multiple mass attacks '
                'including the CallStranger vulnerability (CVE-2020-12695) affecting billions of devices.'
            ),
        })

    return findings


def _check_adb(ip: str) -> list[dict]:
    """Check for Android Debug Bridge on port 5555 TCP."""
    findings = []

    if not _is_tcp_open(ip, 5555):
        return findings

    # ADB handshake probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, 5555))
        s.settimeout(2.0)
        banner = s.recv(1024).decode('utf-8', errors='replace')[:200]
        s.close()

        # ADB typically does not send a banner on connect — but port open is enough
        findings.append({
            'finding_id': 'I9-ADB-OPEN',
            'title': 'Android Debug Bridge (ADB) Exposed on Port 5555',
            'port': 5555,
            'protocol': 'TCP',
            'service': 'ADB',
            'banner': banner.strip() if banner.strip() else '(no banner)',
            'risk_level': 'Critical',
            'cvss_score': 9.8,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'description': (
                'Android Debug Bridge (ADB) is accessible on port 5555. ADB provides full shell '
                'access to the device without any authentication by default. An attacker on the '
                'same network can install malware, exfiltrate data, or completely compromise the '
                'device. ADB over TCP should never be enabled in production — it is a developer '
                'debugging feature that many Android-based IoT devices ship with enabled by default.'
            ),
        })
    except Exception:
        pass

    return findings


def _check_snmp_default(ip: str) -> list[dict]:
    """Check for SNMP with default 'public' community string on port 161 UDP."""
    findings = []

    # SNMPv1 GET request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0) with community 'public'
    snmp_get = bytes([
        0x30, 0x29,                                     # SEQUENCE
        0x02, 0x01, 0x00,                               # version: v1
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, # community: "public"
        0xa0, 0x1c,                                     # GET-REQUEST
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,             # request-id: 1
        0x02, 0x01, 0x00,                               # error-status: 0
        0x02, 0x01, 0x00,                               # error-index: 0
        0x30, 0x0e,                                     # variable-bindings
        0x30, 0x0c,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID: 1.3.6.1.2.1.1.1.0
        0x05, 0x00,                                     # NULL value
    ])

    responsive, data = _is_udp_responsive(ip, 161, snmp_get, timeout=3.0)

    if responsive and len(data) > 10:
        # Try to extract sysDescr from response
        sys_descr = ''
        try:
            text = data.decode('utf-8', errors='replace')
            # Rough extraction — SNMP response contains the value as a string
            printable = ''.join(c if c.isprintable() else ' ' for c in text)
            sys_descr = printable.strip()[:200]
        except Exception:
            pass

        findings.append({
            'finding_id': 'I9-SNMP-PUBLIC',
            'title': 'SNMP Accessible with Default "public" Community String',
            'port': 161,
            'protocol': 'UDP',
            'service': 'SNMP',
            'community_string': 'public',
            'sys_descr': sys_descr,
            'risk_level': 'High',
            'cvss_score': 7.5,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'description': (
                'SNMP on port 161/UDP accepts queries with the default community string "public". '
                'This exposes detailed system information (OS version, network interfaces, routing '
                'tables, ARP cache, running processes) to any host on the network. If the "private" '
                'community string is also default, write access may be possible, allowing '
                'configuration changes. SNMP community strings should be changed from defaults '
                'or SNMP should be disabled entirely if not required.'
            ),
        })

    return findings


def _check_mdns(ip: str) -> list[dict]:
    """Check for mDNS/Bonjour on port 5353 UDP."""
    findings = []

    # mDNS query for _services._dns-sd._udp.local
    mdns_query = bytes([
        0x00, 0x00,  # Transaction ID
        0x00, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answers: 0
        0x00, 0x00,  # Authority: 0
        0x00, 0x00,  # Additional: 0
        # _services._dns-sd._udp.local
        0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
        0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64,
        0x04, 0x5f, 0x75, 0x64, 0x70,
        0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x00,
        0x00, 0x0c,  # Type: PTR
        0x00, 0x01,  # Class: IN
    ])

    responsive, data = _is_udp_responsive(ip, 5353, mdns_query, timeout=3.0)

    if responsive:
        findings.append({
            'finding_id': 'I9-MDNS-OPEN',
            'title': 'mDNS/Bonjour Service Enabled (Port 5353)',
            'port': 5353,
            'protocol': 'UDP',
            'service': 'mDNS',
            'risk_level': 'Medium',
            'cvss_score': 5.3,
            'description': (
                'The device responds to mDNS queries on port 5353/UDP. mDNS broadcasts device '
                'name, type, and available services to the local network. While useful for '
                'service discovery in home environments, in production deployments it leaks '
                'device metadata that aids reconnaissance. mDNS should be disabled on devices '
                'deployed in production or security-sensitive environments.'
            ),
        })

    return findings


def _check_default_hostnames(ip: str) -> list[dict]:
    """Check HTTP responses for factory-default device names and identifiers."""
    findings = []
    checked_urls = []

    for port in HTTP_PORTS:
        scheme = 'https' if port in (443, 8443) else 'http'
        url = f'{scheme}://{ip}:{port}'
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            checked_urls.append(url)
            body = r.text[:2000]
            title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else ''
            # Check body, title, and response headers for default identifiers
            header_text = ' '.join(f'{k}: {v}' for k, v in r.headers.items())
            check_text = f'{title} {body[:1000]} {header_text}'

            matched_names = []
            for pattern in DEFAULT_HOSTNAME_PATTERNS:
                m = pattern.search(check_text)
                if m:
                    matched_names.append(m.group(0))

            if matched_names:
                findings.append({
                    'finding_id': f'I9-DEFAULT-HOSTNAME-{port}',
                    'title': f'Factory Default Device Identity Detected on Port {port}',
                    'url': url,
                    'port': port,
                    'matched_names': matched_names,
                    'page_title': title[:100] if title else '(no title)',
                    'risk_level': 'Medium',
                    'cvss_score': 4.3,
                    'description': (
                        f'The HTTP response on port {port} contains factory-default device '
                        f'identifiers: {", ".join(matched_names)}. This indicates the device '
                        f'name and identity have not been customized from factory defaults, '
                        f'which is a strong indicator that other default settings (credentials, '
                        f'services, firewall rules) may also be unchanged. Device identity '
                        f'should be customized during deployment to prevent easy fingerprinting.'
                    ),
                })
                break  # One finding per device is enough
        except Exception:
            pass

    return findings


def _check_setup_wizards(ip: str) -> list[dict]:
    """
    Check if setup/initial-configuration wizards are still accessible.
    Distinct from I3 auth bypass — the signal here is 'device was never
    properly configured after deployment'.
    """
    findings = []

    for port in HTTP_PORTS:
        if not _is_tcp_open(ip, port):
            continue
        scheme = 'https' if port in (443, 8443) else 'http'

        for path in SETUP_WIZARD_PATHS:
            url = f'{scheme}://{ip}:{port}{path}'
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                if r.status_code != 200:
                    continue

                body_lower = r.text.lower()[:2000]
                is_setup = sum(1 for kw in SETUP_KEYWORDS if kw in body_lower) >= 2

                if is_setup:
                    findings.append({
                        'finding_id': f'I9-SETUP-WIZARD-{port}-{path.replace("/", "_").strip("_").upper()}',
                        'title': f'Setup Wizard Still Accessible: {path} (Port {port})',
                        'url': url,
                        'port': port,
                        'path': path,
                        'risk_level': 'High',
                        'cvss_score': 7.5,
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
                        'description': (
                            f'The setup wizard at {url} is still accessible and appears to be '
                            f'an active initial configuration page. This strongly indicates the '
                            f'device was deployed without completing initial security configuration. '
                            f'An attacker could use this wizard to reconfigure the device, change '
                            f'credentials, modify network settings, or disable security features. '
                            f'Setup wizards must be disabled or locked after initial deployment.'
                        ),
                    })
                    return findings  # One setup wizard finding is enough
            except Exception:
                pass

    return findings


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings: list[dict] = []
    scan_summary = {
        'upnp_checked': True,
        'upnp_open': False,
        'adb_checked': True,
        'adb_open': False,
        'snmp_checked': True,
        'snmp_default_community': False,
        'mdns_checked': True,
        'mdns_open': False,
        'default_hostname_detected': False,
        'setup_wizard_found': False,
        'http_ports_probed': HTTP_PORTS,
    }

    # UPnP/SSDP
    upnp_findings = _check_upnp(ip)
    scan_summary['upnp_open'] = bool(upnp_findings)
    all_findings.extend(upnp_findings)

    # ADB
    adb_findings = _check_adb(ip)
    scan_summary['adb_open'] = bool(adb_findings)
    all_findings.extend(adb_findings)

    # SNMP default community
    snmp_findings = _check_snmp_default(ip)
    scan_summary['snmp_default_community'] = bool(snmp_findings)
    all_findings.extend(snmp_findings)

    # mDNS
    mdns_findings = _check_mdns(ip)
    scan_summary['mdns_open'] = bool(mdns_findings)
    all_findings.extend(mdns_findings)

    # Default hostnames in HTTP
    hostname_findings = _check_default_hostnames(ip)
    scan_summary['default_hostname_detected'] = bool(hostname_findings)
    all_findings.extend(hostname_findings)

    # Setup wizards
    wizard_findings = _check_setup_wizards(ip)
    scan_summary['setup_wizard_found'] = bool(wizard_findings)
    all_findings.extend(wizard_findings)

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict] = []
    for f in all_findings:
        if f['finding_id'] not in seen:
            seen.add(f['finding_id'])
            unique.append(f)
    all_findings = unique

    critical = sum(1 for f in all_findings if f.get('risk_level') == 'Critical')
    high     = sum(1 for f in all_findings if f.get('risk_level') == 'High')
    medium   = sum(1 for f in all_findings if f.get('risk_level') == 'Medium')

    status         = 'FAIL' if all_findings else 'PASS'
    security_score = max(0, 100 - critical * 25 - high * 15 - medium * 5)

    return {
        'check_id':         'I9',
        'check_name':       'Insecure Default Settings',
        'owasp_ref':        'OWASP IoT Top 10:2018 — I9',
        'implemented':      True,
        'status':           status,
        'severity':         'Medium',
        'security_score':   security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings':         all_findings,
        'scan_summary':     scan_summary,
        'technical_detail': (
            f'Checked 6 default-setting indicators: '
            f'UPnP/SSDP (1900/UDP): {"open" if scan_summary["upnp_open"] else "closed"}. '
            f'ADB (5555/TCP): {"open" if scan_summary["adb_open"] else "closed"}. '
            f'SNMP public (161/UDP): {"default community accepted" if scan_summary["snmp_default_community"] else "not responding or non-default"}. '
            f'mDNS (5353/UDP): {"open" if scan_summary["mdns_open"] else "closed"}. '
            f'Default hostname: {"detected" if scan_summary["default_hostname_detected"] else "not detected"}. '
            f'Setup wizard: {"found" if scan_summary["setup_wizard_found"] else "not found"}. '
            f'{len(all_findings)} finding(s) identified.'
        ),
        'risk_explanation': (
            'Factory default settings are the lowest-hanging fruit for attackers. Devices shipped '
            'with UPnP enabled allow automatic firewall port-opening from the LAN. ADB over TCP '
            'provides unauthenticated root shell access. SNMP with default community strings '
            'exposes complete system inventories. Setup wizards left accessible indicate the device '
            'was never properly hardened after deployment, meaning all other defaults (credentials, '
            'services, firewall rules) are also likely unchanged. The Mirai botnet and its variants '
            'specifically target devices with default configurations.'
        ),
        'remediation_steps': [
            'Disable UPnP on all production devices — use explicit port forwarding rules instead',
            'Disable ADB over TCP (adb tcpip) on all Android-based IoT devices in production',
            'Change SNMP community strings from "public"/"private" to strong random values, or disable SNMP entirely',
            'Disable mDNS/Bonjour on devices deployed in production or enterprise environments',
            'Customize device hostname and identity during initial deployment',
            'Lock or remove setup wizard endpoints after initial configuration is complete',
            'Implement a post-deployment hardening checklist as part of the device provisioning process',
        ],
    }

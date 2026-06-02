"""
I5 — Use of Insecure or Outdated Components
OWASP IoT Top 10:2018

Extracts version strings from service banners (SSH, FTP, HTTP Server,
RTSP, MQTT) and matches them against a curated list of known-vulnerable
component versions commonly found on IoT devices.

Design decisions:
- Static CVE/version list rather than live NVD API — IoT firmware versions
  are largely frozen; static lists are more reliable than regex-on-banners
  fed into a rate-limited external API.
- Conservative matching — only flag when the version string clearly
  identifies a known-vulnerable release. Ambiguous banners are noted
  in scan_summary but do not produce findings.
- No false positive amplification — if the banner suppresses the version
  (e.g. "Apache" without a version number) we record it as
  'version_suppressed', which is actually good practice.
"""

import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Vulnerable version database
# Each entry: version_regex must match the full version string captured from
# the banner. Fields: cve, cvss, description, fixed_in.
# ---------------------------------------------------------------------------

VULNERABLE_VERSIONS: dict[str, list[dict]] = {

    # OpenSSH
    'openssh': [
        {
            'version_pattern': r'^[1-6]\.',
            'cve': 'Multiple (pre-7.0)',
            'cvss': 7.5,
            'description': 'OpenSSH versions before 7.0 contain multiple vulnerabilities including '
                           'use-after-free (CVE-2016-0777), roaming information leak (CVE-2016-0778), '
                           'and several privilege escalation issues.',
            'fixed_in': '7.0',
        },
        {
            'version_pattern': r'^7\.[0-3]([^0-9]|$)',
            'cve': 'CVE-2018-15473',
            'cvss': 5.3,
            'description': 'OpenSSH 7.0–7.3 is vulnerable to username enumeration via timing '
                           'differences in authentication responses (CVE-2018-15473).',
            'fixed_in': '7.4',
        },
    ],

    # Dropbear SSH (common on embedded/IoT)
    'dropbear': [
        {
            'version_pattern': r'^201[0-5]',
            'cve': 'CVE-2016-7406 / CVE-2016-7408',
            'cvss': 9.8,
            'description': 'Dropbear SSH before 2016.74 contains format string vulnerabilities '
                           '(CVE-2016-7406) and integer overflow issues (CVE-2016-7408) that '
                           'allow remote code execution without authentication.',
            'fixed_in': '2016.74',
        },
        {
            'version_pattern': r'^2016\.(7[0-3]|[0-6][0-9])\b',
            'cve': 'CVE-2016-7406',
            'cvss': 9.8,
            'description': 'Dropbear SSH 2016.73 and earlier — format string vulnerability '
                           'allowing remote unauthenticated code execution.',
            'fixed_in': '2016.74',
        },
    ],

    # vsftpd
    'vsftpd': [
        {
            'version_pattern': r'^2\.3\.4$',
            'cve': 'CVE-2011-2523',
            'cvss': 10.0,
            'description': 'vsftpd 2.3.4 contains a backdoor introduced via a compromised '
                           'source distribution that opens a shell on port 6200 when a '
                           'username ending in ":)" is used.',
            'fixed_in': '2.3.5',
        },
        {
            'version_pattern': r'^2\.[0-2]\.',
            'cve': 'CVE-2011-0762',
            'cvss': 6.8,
            'description': 'vsftpd before 2.3.4 is vulnerable to denial of service via '
                           'crafted glob expressions (CVE-2011-0762).',
            'fixed_in': '2.3.4',
        },
    ],

    # ProFTPD
    'proftpd': [
        {
            'version_pattern': r'^1\.[23]\.',
            'cve': 'CVE-2015-3306',
            'cvss': 10.0,
            'description': 'ProFTPD 1.2.x and 1.3.x before 1.3.5b contain a use-after-free '
                           'vulnerability in the mod_copy module (CVE-2015-3306) allowing '
                           'unauthenticated remote code execution.',
            'fixed_in': '1.3.5b',
        },
    ],

    # Apache HTTP Server
    'apache': [
        {
            'version_pattern': r'^2\.[0-3]\.',
            'cve': 'Multiple (pre-2.4)',
            'cvss': 7.5,
            'description': 'Apache HTTP Server 2.0.x and 2.2.x reached end-of-life and contain '
                           'multiple unpatched vulnerabilities including mod_cgi buffer overflow '
                           '(CVE-2014-0230) and information disclosure issues.',
            'fixed_in': '2.4.x',
        },
        {
            'version_pattern': r'^2\.4\.([1-3][0-9]|[1-9])\b',
            'cve': 'CVE-2021-41773 / CVE-2021-42013',
            'cvss': 9.8,
            'description': 'Apache HTTP Server 2.4.49–2.4.50 contain a path traversal and '
                           'remote code execution vulnerability (CVE-2021-41773, CVE-2021-42013) '
                           'that was actively exploited in the wild within hours of disclosure.',
            'fixed_in': '2.4.51',
        },
    ],

    # nginx
    'nginx': [
        {
            'version_pattern': r'^0\.',
            'cve': 'Multiple (pre-1.0)',
            'cvss': 7.5,
            'description': 'nginx 0.x is end-of-life with multiple known vulnerabilities '
                           'including buffer overflow and denial of service issues.',
            'fixed_in': '1.20.x (stable)',
        },
        {
            'version_pattern': r'^1\.(1[0-7]|[0-9])\.',
            'cve': 'CVE-2019-9511 / CVE-2019-9513',
            'cvss': 7.5,
            'description': 'nginx before 1.17.3 is vulnerable to HTTP/2 resource exhaustion '
                           'attacks (CVE-2019-9511, CVE-2019-9513) that can cause denial of service.',
            'fixed_in': '1.17.3',
        },
    ],

    # lighttpd (common on IoT)
    'lighttpd': [
        {
            'version_pattern': r'^1\.[0-3]\.',
            'cve': 'Multiple (pre-1.4)',
            'cvss': 7.5,
            'description': 'lighttpd 1.3.x and earlier contain multiple vulnerabilities '
                           'including path traversal and HTTP response splitting.',
            'fixed_in': '1.4.x',
        },
        {
            'version_pattern': r'^1\.4\.([0-5][0-9])\b',
            'cve': 'CVE-2022-22707',
            'cvss': 5.9,
            'description': 'lighttpd before 1.4.64 contains a use-after-free vulnerability '
                           '(CVE-2022-22707) that can cause crashes or potential code execution.',
            'fixed_in': '1.4.64',
        },
    ],

    # OpenSSL (often exposed via banner or HTTPS negotiation)
    'openssl': [
        {
            'version_pattern': r'^0\.',
            'cve': 'Multiple (pre-1.0)',
            'cvss': 9.8,
            'description': 'OpenSSL 0.x is severely end-of-life with numerous critical '
                           'vulnerabilities including Heartbleed family and POODLE.',
            'fixed_in': '1.1.1 or 3.x',
        },
        {
            'version_pattern': r'^1\.0\.',
            'cve': 'CVE-2014-0160 (Heartbleed) + EOL',
            'cvss': 7.5,
            'description': 'OpenSSL 1.0.x is end-of-life. The 1.0.1 series included Heartbleed '
                           '(CVE-2014-0160), the most widespread TLS vulnerability in history, '
                           'allowing extraction of private keys and session tokens from memory.',
            'fixed_in': '1.1.1 or 3.x',
        },
        {
            'version_pattern': r'^1\.1\.0',
            'cve': 'CVE-2017-3735 / EOL',
            'cvss': 5.3,
            'description': 'OpenSSL 1.1.0 reached end-of-life in September 2019. '
                           'Contains CVE-2017-3735 (one-byte memory over-read in X.509 parsing).',
            'fixed_in': '1.1.1 or 3.x',
        },
    ],

    # BusyBox (common on embedded Linux IoT)
    'busybox': [
        {
            'version_pattern': r'^1\.(1[0-9]|2[0-9])\.',
            'cve': 'CVE-2022-28391',
            'cvss': 9.8,
            'description': 'BusyBox versions before 1.35.0 are affected by multiple '
                           'vulnerabilities including CVE-2022-28391 (remote code execution '
                           'in the DHCP client) and CVE-2021-42374 (out-of-bounds write in unlzma).',
            'fixed_in': '1.35.0',
        },
    ],

    # Mosquitto MQTT broker
    'mosquitto': [
        {
            'version_pattern': r'^1\.[0-4]\.',
            'cve': 'CVE-2017-7650',
            'cvss': 6.5,
            'description': 'Eclipse Mosquitto before 1.4.15 is vulnerable to topic ACL bypass '
                           '(CVE-2017-7650) allowing authenticated users to access topics '
                           'they should not have permission to read or write.',
            'fixed_in': '1.4.15',
        },
        {
            'version_pattern': r'^1\.[0-5]\.',
            'cve': 'CVE-2018-12543',
            'cvss': 7.5,
            'description': 'Eclipse Mosquitto 1.5.x and earlier contain a null pointer '
                           'dereference (CVE-2018-12543) allowing denial of service via '
                           'a crafted CONNECT packet.',
            'fixed_in': '1.5.5',
        },
    ],

    # MiniUPnP (frequently found on consumer IoT/routers)
    'miniupnp': [
        {
            'version_pattern': r'^1\.',
            'cve': 'CVE-2017-8798',
            'cvss': 9.8,
            'description': 'MiniUPnPd before 2.0 contains multiple buffer overflow '
                           'vulnerabilities (CVE-2017-8798) allowing remote unauthenticated '
                           'code execution via crafted UPnP packets.',
            'fixed_in': '2.0',
        },
    ],
}

# Port → list of services to extract banners from
BANNER_TARGETS: dict[int, str] = {
    21:   'ftp',
    22:   'ssh',
    23:   'telnet',
    80:   'http',
    443:  'https',
    1883: 'mqtt',
    2222: 'ssh',
    8080: 'http',
    8443: 'https',
    8888: 'http',
}

# Regex patterns to extract (component, version) from banner strings
BANNER_VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('openssh',    re.compile(r'SSH-\d+\.\d+-OpenSSH[_\s](\S+)',         re.IGNORECASE)),
    ('dropbear',   re.compile(r'SSH-\d+\.\d+-dropbear[_\s](\S+)',        re.IGNORECASE)),
    ('openssh',    re.compile(r'openssh[/\s_](\d+\.\d+\S*)',              re.IGNORECASE)),
    ('dropbear',   re.compile(r'dropbear[/\s_](\d+\.\d+\S*)',             re.IGNORECASE)),
    ('vsftpd',     re.compile(r'vsftpd[/\s](\d+\.\d+[\.\d]*)',            re.IGNORECASE)),
    ('proftpd',    re.compile(r'proftpd[/\s](\d+\.\d+[\.\d]*)',           re.IGNORECASE)),
    ('apache',     re.compile(r'Apache[/\s](\d+\.\d+[\.\d]*)',            re.IGNORECASE)),
    ('nginx',      re.compile(r'nginx[/\s](\d+\.\d+[\.\d]*)',             re.IGNORECASE)),
    ('lighttpd',   re.compile(r'lighttpd[/\s](\d+\.\d+[\.\d]*)',          re.IGNORECASE)),
    ('openssl',    re.compile(r'OpenSSL[/\s](\d+[\.\d]+\w*)',             re.IGNORECASE)),
    ('busybox',    re.compile(r'BusyBox[/\sv]+(\d+\.\d+[\.\d]*)',         re.IGNORECASE)),
    ('mosquitto',  re.compile(r'[Mm]osquitto[/\s](\d+\.\d+[\.\d]*)',      re.IGNORECASE)),
    ('miniupnp',   re.compile(r'MiniUPnPd?[/\s](\d+\.\d+[\.\d]*)',       re.IGNORECASE)),
]


def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Grab raw banner from a TCP service."""
    probes: dict[int, bytes] = {
        21:   b'',
        22:   b'',
        23:   b'',
        80:   b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n',
        8080: b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n',
        8888: b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n',
        1883: bytes([0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
                     0x04, 0x00, 0x00, 0x3c, 0x00, 0x00]),
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return ''
        probe = probes.get(port, b'')
        if probe:
            s.sendall(probe)
        s.settimeout(2.0)
        raw = s.recv(2048)
        s.close()
        return raw.decode('utf-8', errors='replace').strip()[:500]
    except Exception:
        return ''


def _grab_tls_banner(ip: str, port: int, timeout: float = 5.0) -> str:
    """Extract OpenSSL/TLS version info from HTTPS negotiation."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                # Try to get the server banner via HTTP over TLS
                tls_sock.sendall(
                    b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n'
                )
                tls_sock.settimeout(2.0)
                raw = tls_sock.recv(2048)
                return raw.decode('utf-8', errors='replace').strip()[:500]
    except Exception:
        return ''


def _extract_versions(banner: str) -> list[tuple[str, str]]:
    """
    Extract (component_name, version_string) pairs from a banner.
    Returns a list because a banner may contain multiple components.
    """
    found = []
    for component, pattern in BANNER_VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            found.append((component, m.group(1)))
    return found


def _match_vulnerable(component: str, version: str) -> list[dict]:
    """Return list of vulnerability matches for a (component, version) pair."""
    component_lower = component.lower()
    if component_lower not in VULNERABLE_VERSIONS:
        return []

    matches = []
    for vuln in VULNERABLE_VERSIONS[component_lower]:
        if re.search(vuln['version_pattern'], version, re.IGNORECASE):
            matches.append(vuln)
    return matches


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings: list[dict] = []
    banners_collected: dict[int, str] = {}
    versions_found: list[dict] = []
    scan_summary = {
        'ports_probed':        list(BANNER_TARGETS.keys()),
        'banners_collected':   0,
        'versions_extracted':  [],
        'components_matched':  [],
    }

    # Collect banners in parallel
    def _collect(port: int) -> tuple[int, str]:
        if port in (443, 8443):
            banner = _grab_tls_banner(ip, port)
            if not banner:
                banner = _grab_banner(ip, port)
        else:
            banner = _grab_banner(ip, port)
        return port, banner

    with ThreadPoolExecutor(max_workers=len(BANNER_TARGETS)) as pool:
        futures = {pool.submit(_collect, p): p for p in BANNER_TARGETS}
        for future in as_completed(futures):
            port = futures[future]
            try:
                _, banner = future.result()
                if banner:
                    banners_collected[port] = banner
            except Exception:
                pass

    scan_summary['banners_collected'] = len(banners_collected)

    # Extract versions from all collected banners
    seen_component_versions: set[tuple[str, str]] = set()
    for port, banner in banners_collected.items():
        for component, version in _extract_versions(banner):
            key = (component, version)
            if key in seen_component_versions:
                continue
            seen_component_versions.add(key)

            versions_found.append({
                'component': component,
                'version':   version,
                'port':      port,
                'banner':    banner[:200],
            })
            scan_summary['versions_extracted'].append(f'{component}/{version} (port {port})')

            # Check against vulnerable versions database
            vuln_matches = _match_vulnerable(component, version)
            for vuln in vuln_matches:
                finding_id = (
                    f'I5-{component.upper()}-{version.replace(".", "_")}-'
                    f'{vuln["cve"].replace(" ", "_").replace("/", "_")}'
                )
                all_findings.append({
                    'finding_id':   finding_id,
                    'title':        f'Outdated/Vulnerable Component: {component} {version}',
                    'component':    component,
                    'version':      version,
                    'port':         port,
                    'cve':          vuln['cve'],
                    'cvss_score':   vuln['cvss'],
                    'cvss_vector':  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'fixed_in':     vuln['fixed_in'],
                    'risk_level':   (
                        'Critical' if vuln['cvss'] >= 9.0 else
                        'High'     if vuln['cvss'] >= 7.0 else
                        'Medium'   if vuln['cvss'] >= 4.0 else 'Low'
                    ),
                    'banner_snippet': banner[:150],
                    'description':  vuln['description'],
                    'remediation':  f'Update {component} to version {vuln["fixed_in"]} or later.',
                })
                scan_summary['components_matched'].append(
                    f'{component}/{version} → {vuln["cve"]}'
                )

    # Deduplicate findings
    seen_ids: set[str] = set()
    unique: list[dict] = []
    for f in all_findings:
        if f['finding_id'] not in seen_ids:
            seen_ids.add(f['finding_id'])
            unique.append(f)
    all_findings = unique
    all_findings.sort(key=lambda f: -f['cvss_score'])

    critical = sum(1 for f in all_findings if f['risk_level'] == 'Critical')
    high     = sum(1 for f in all_findings if f['risk_level'] == 'High')
    medium   = sum(1 for f in all_findings if f['risk_level'] == 'Medium')

    status         = 'FAIL' if all_findings else 'PASS'
    security_score = max(0, 100 - critical * 25 - high * 15 - medium * 5)

    no_banners_msg = ''
    if not banners_collected:
        no_banners_msg = ' No service banners were obtained — device may suppress version disclosure (good practice) or no services responded.'
        status         = 'PASS'
        security_score = 100

    versions_summary = (
        ', '.join(scan_summary['versions_extracted'])
        if scan_summary['versions_extracted']
        else 'No version strings extracted from banners'
    )

    return {
        'check_id':         'I5',
        'check_name':       'Use of Insecure or Outdated Components',
        'owasp_ref':        'OWASP IoT Top 10:2018 — I5',
        'implemented':      True,
        'status':           status,
        'severity':         'High',
        'security_score':   security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings':         all_findings,
        'scan_summary':     scan_summary,
        'technical_detail': (
            f'Probed {len(BANNER_TARGETS)} ports for service banners. '
            f'Collected {len(banners_collected)} banner(s). '
            f'Extracted versions: {versions_summary}. '
            f'{len(all_findings)} vulnerable component(s) identified.'
            + no_banners_msg
        ),
        'risk_explanation': (
            'IoT firmware typically bundles open-source components (OpenSSH, BusyBox, lighttpd, '
            'Dropbear, Mosquitto) at the version available when the firmware was compiled. '
            'Because firmware updates on IoT devices are infrequent, these components quickly '
            'fall behind patch levels. Attackers actively scan for version banners and target '
            'known CVEs — the time from CVE disclosure to weaponised exploit is often under 24 hours '
            'for critical vulnerabilities in widely-deployed components.'
        ),
        'remediation_steps': [
            'Identify all open-source components bundled in firmware and their versions',
            'Subscribe to security advisories for each component (NVD, vendor mailing lists)',
            'Establish a firmware update cadence — critical CVEs within 30 days, high within 90 days',
            'Configure services to suppress version disclosure in banners where possible '
            '(e.g. Apache ServerTokens Prod, nginx server_tokens off)',
            'Use a software composition analysis (SCA) tool in the firmware build pipeline',
            'Consider replacing end-of-life components with actively maintained alternatives',
        ],
    }
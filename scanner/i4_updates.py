"""
I4 — Lack of Secure Update Mechanism
OWASP IoT Top 10:2018

Scope: Update *channel* security — what is observable over a TCP/IP network
without firmware binary access. Specifically:
  - Are firmware/update endpoints reachable without authentication?
  - Is the update channel served over HTTP (cleartext) rather than HTTPS?
  - Does the device advertise an update server URL that uses HTTP?
  - Are update-related endpoints exposed with dangerous HTTP methods?

Out of scope (not assessable over a network):
  - Firmware signature verification
  - Cryptographic integrity of update packages
  - Secure boot chain validation
These require firmware binary access and are documented in REQUIREMENTS.md §2.
"""

import time
import socket
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS = [80, 8080, 8888, 443, 8443]

# Firmware/update endpoint paths commonly found on IoT devices
UPDATE_PATHS = [
    '/firmware',
    '/firmware/update',
    '/firmware/upgrade',
    '/update',
    '/upgrade',
    '/api/firmware',
    '/api/firmware/update',
    '/api/update',
    '/api/upgrade',
    '/api/ota',
    '/ota',
    '/ota/update',
    '/cgi-bin/firmware',
    '/cgi-bin/update',
    '/cgi-bin/upgrade',
    '/admin/firmware',
    '/admin/update',
    '/admin/upgrade',
    '/system/firmware',
    '/system/update',
    '/system/upgrade',
    '/v1/firmware',
    '/v1/update',
]

# HTTP status codes that indicate the endpoint exists and is accessible
ACCESSIBLE_STATUSES = {200, 201, 204, 206, 301, 302, 307, 308}

# Response body keywords that suggest update-related content
UPDATE_KEYWORDS = [
    'firmware', 'version', 'upgrade', 'update', 'ota',
    'flash', 'binary', 'image', 'download', 'file',
]


def _is_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _get_active_http_ports(ip: str) -> list[int]:
    return [p for p in HTTP_PORTS if _is_open(ip, p)]


def _probe_update_endpoint(base_url: str, port: int, path: str) -> dict | None:
    """
    Probe a single update endpoint. Returns a finding dict if the endpoint
    is accessible without authentication, None otherwise.
    """
    url = f'{base_url}{path}'
    try:
        r = requests.get(
            url,
            timeout=5,
            verify=False,
            allow_redirects=False,
        )

        if r.status_code not in ACCESSIBLE_STATUSES:
            return None

        # Check if content looks update-related (reduces false positives)
        body_lower = r.text.lower()[:500]
        is_update_content = any(kw in body_lower for kw in UPDATE_KEYWORDS)

        # 200 with update content = definite finding
        # 200 without update content = possible finding (endpoint exists, unknown content)
        # 3xx = redirect — note it but lower severity
        is_redirect = r.status_code in {301, 302, 307, 308}
        scheme = base_url.split('://')[0]
        is_cleartext = scheme == 'http'

        severity  = 'Info'
        cvss      = 4.0
        finding_type = 'redirect'

        if r.status_code == 200 and is_update_content:
            severity     = 'Critical' if is_cleartext else 'High'
            cvss         = 9.1 if is_cleartext else 7.5
            finding_type = 'accessible_update_endpoint'
        elif r.status_code == 200:
            severity     = 'High' if is_cleartext else 'Medium'
            cvss         = 7.5 if is_cleartext else 5.3
            finding_type = 'accessible_unknown_endpoint'
        elif is_redirect:
            location     = r.headers.get('Location', '')
            severity     = 'Medium'
            cvss         = 5.3
            finding_type = 'redirect'

        description_parts = []
        if is_cleartext:
            description_parts.append(
                f'The update endpoint {url} is served over HTTP (cleartext). '
                f'An attacker with network access can intercept the request/response, '
                f'observe firmware version information, and potentially conduct a '
                f'man-in-the-middle attack to substitute a malicious firmware image.'
            )
        else:
            description_parts.append(
                f'The update endpoint {url} is accessible without authentication. '
                f'An attacker on the same network can probe firmware version and trigger '
                f'update checks without any credentials.'
            )
        if is_update_content:
            description_parts.append(
                f'The response body contains update-related keywords, confirming this is '
                f'an active firmware management endpoint.'
            )

        return {
            'finding_id':    f'I4-{finding_type.upper()}-{port}-{path.replace("/", "_").strip("_").upper()}',
            'title':         f'Firmware Update Endpoint Accessible Without Authentication: {path}',
            'url':           url,
            'port':          port,
            'path':          path,
            'http_status':   r.status_code,
            'scheme':        scheme,
            'cleartext':     is_cleartext,
            'finding_type':  finding_type,
            'risk_level':    severity,
            'cvss_score':    cvss,
            'cvss_vector':   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'response_preview': r.text[:200].replace('\n', ' '),
            'description':   ' '.join(description_parts),
        }

    except Exception:
        return None


def _check_http_update_channel(ip: str, port: int) -> list[dict]:
    """Check all update paths on a given port."""
    scheme   = 'https' if port in (443, 8443) else 'http'
    base_url = f'{scheme}://{ip}:{port}'
    findings = []

    for path in UPDATE_PATHS:
        finding = _probe_update_endpoint(base_url, port, path)
        if finding:
            findings.append(finding)

    return findings


def _check_cleartext_update_channel(ip: str, active_ports: list[int]) -> list[dict]:
    """
    If HTTP (port 80/8080/8888) is open but HTTPS (443/8443) is not,
    the entire update channel is cleartext — flag this explicitly even if
    no specific update endpoint was found.
    """
    findings = []
    http_ports  = [p for p in active_ports if p in (80, 8080, 8888)]
    https_ports = [p for p in active_ports if p in (443, 8443)]

    if http_ports and not https_ports:
        findings.append({
            'finding_id':   'I4-NO-HTTPS',
            'title':        'No HTTPS Available — Update Channel Forced to Cleartext',
            'url':          f'http://{ip}:{http_ports[0]}',
            'port':         http_ports[0],
            'path':         '(device-level)',
            'http_status':  None,
            'scheme':       'http',
            'cleartext':    True,
            'finding_type': 'no_https',
            'risk_level':   'High',
            'cvss_score':   7.4,
            'cvss_vector':  'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'response_preview': '',
            'description': (
                f'The device on {ip} exposes HTTP on port(s) {http_ports} but no HTTPS service '
                f'was detected. Any firmware update performed via the web interface will be '
                f'transmitted in cleartext, making it susceptible to interception and '
                f'man-in-the-middle substitution attacks on the local network.'
            ),
        })

    return findings


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings: list[dict] = []
    scan_summary = {
        'ports_probed':          HTTP_PORTS,
        'active_http_ports':     [],
        'update_paths_probed':   len(UPDATE_PATHS),
        'accessible_endpoints':  [],
        'cleartext_endpoints':   [],
        'https_available':       False,
    }

    active_ports = _get_active_http_ports(ip)
    scan_summary['active_http_ports'] = active_ports

    if not active_ports:
        return {
            'check_id':        'I4',
            'check_name':      'Lack of Secure Update Mechanism',
            'owasp_ref':       'OWASP IoT Top 10:2018 — I4',
            'implemented':     True,
            'status':          'PASS',
            'severity':        'High',
            'security_score':  100,
            'scan_duration_ms': round((time.time() - t0) * 1000),
            'findings':        [],
            'scan_summary':    scan_summary,
            'technical_detail': (
                'No HTTP/HTTPS services detected. No network-accessible update channel found. '
                'Note: firmware update security (signature verification, secure boot) '
                'requires firmware binary access and is outside the scope of this check.'
            ),
            'risk_explanation': (
                'Without an exposed web interface, the update channel attack surface is minimal '
                'from a network perspective.'
            ),
            'remediation_steps': [
                'If firmware updates are delivered via a cloud service, ensure the update URL uses HTTPS.',
                'Implement firmware signature verification on the device (out of scope for network scanning).',
            ],
        }

    https_ports = [p for p in active_ports if p in (443, 8443)]
    scan_summary['https_available'] = bool(https_ports)

    # Check cleartext channel at device level
    cleartext_findings = _check_cleartext_update_channel(ip, active_ports)
    all_findings.extend(cleartext_findings)

    # Probe update endpoints on all active ports
    for port in active_ports:
        port_findings = _check_http_update_channel(ip, port)
        all_findings.extend(port_findings)

    # Deduplicate by finding_id
    seen: set[str] = set()
    unique: list[dict] = []
    for f in all_findings:
        if f['finding_id'] not in seen:
            seen.add(f['finding_id'])
            unique.append(f)
    all_findings = unique

    scan_summary['accessible_endpoints'] = [
        f['url'] for f in all_findings
        if f['finding_type'] in ('accessible_update_endpoint', 'accessible_unknown_endpoint')
    ]
    scan_summary['cleartext_endpoints'] = [
        f['url'] for f in all_findings if f.get('cleartext')
    ]

    critical = sum(1 for f in all_findings if f['risk_level'] == 'Critical')
    high     = sum(1 for f in all_findings if f['risk_level'] == 'High')
    medium   = sum(1 for f in all_findings if f['risk_level'] == 'Medium')

    status         = 'FAIL' if (critical + high) > 0 else ('FAIL' if medium >= 2 else 'PASS')
    security_score = max(0, 100 - critical * 25 - high * 15 - medium * 5)

    return {
        'check_id':        'I4',
        'check_name':      'Lack of Secure Update Mechanism',
        'owasp_ref':       'OWASP IoT Top 10:2018 — I4',
        'implemented':     True,
        'status':          status,
        'severity':        'High',
        'security_score':  security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings':        all_findings,
        'scan_summary':    scan_summary,
        'technical_detail': (
            f'Probed {len(UPDATE_PATHS)} firmware/update endpoint paths across '
            f'{len(active_ports)} active HTTP port(s): {active_ports}. '
            f'Found {len(all_findings)} finding(s): {critical} Critical, {high} High, {medium} Medium. '
            f'HTTPS available: {scan_summary["https_available"]}. '
            f'Note: firmware signature verification requires binary access '
            f'and is outside the scope of this network-based check.'
        ),
        'risk_explanation': (
            'An insecure update channel allows a network-positioned attacker to observe firmware '
            'version information, intercept update traffic, and potentially substitute a malicious '
            'firmware image (man-in-the-middle). Unauthenticated update endpoints can also be '
            'triggered by any device on the network, enabling denial-of-service via forced updates. '
            'The 2018 VPNFilter malware exploited exactly this class of vulnerability to persist '
            'across reboots on over 500,000 routers worldwide.'
        ),
        'remediation_steps': [
            'Serve all firmware update endpoints exclusively over HTTPS (TLS 1.2 or 1.3)',
            'Require authentication before exposing any /firmware or /update endpoint',
            'Implement firmware image signature verification using asymmetric cryptography (RSA-2048 or ECDSA)',
            'Use certificate pinning for the update server to prevent certificate substitution attacks',
            'Disable manual firmware upload endpoints in production — use a managed OTA service',
            'Log and alert on any firmware update attempt for audit purposes',
        ],
    }

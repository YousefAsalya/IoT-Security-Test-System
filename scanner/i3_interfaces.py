"""
I3 — Insecure Ecosystem Interfaces
OWASP IoT Top 10:2018

Analyses HTTP-based interfaces for missing security headers, server
information disclosure, unauthenticated endpoint access, CORS
misconfiguration, and permissive HTTP method exposure.
"""

import socket
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS = [80, 8080, 8888, 443, 8443]

SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'description': 'Prevents XSS and code injection attacks by restricting resource origins',
        'severity': 'High',
        'cvss': 6.1,
    },
    'Strict-Transport-Security': {
        'description': 'Forces HTTPS and prevents SSL-stripping downgrade attacks',
        'severity': 'High',
        'cvss': 6.5,
    },
    'X-Frame-Options': {
        'description': 'Prevents the page from being embedded in iframes (clickjacking)',
        'severity': 'Medium',
        'cvss': 4.3,
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME-type sniffing attacks',
        'severity': 'Medium',
        'cvss': 3.7,
    },
    'Referrer-Policy': {
        'description': 'Controls referrer information sent with requests',
        'severity': 'Low',
        'cvss': 3.1,
    },
    'Permissions-Policy': {
        'description': 'Restricts browser feature access (camera, microphone, geolocation)',
        'severity': 'Low',
        'cvss': 3.1,
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS filter for older browsers (superseded by CSP)',
        'severity': 'Low',
        'cvss': 2.4,
    },
}

SENSITIVE_ENDPOINTS = [
    ('/api/config',        'Device configuration (may expose credentials)'),
    ('/api/status',        'Device status (may expose internal info)'),
    ('/api/debug',         'Debug endpoint (may expose stack traces)'),
    ('/debug',             'Debug interface'),
    ('/env',               'Environment variables'),
    ('/admin',             'Admin panel'),
    ('/management',        'Management interface'),
    ('/console',           'Console interface'),
    ('/api/users',         'User list'),
    ('/api/credentials',   'Credentials endpoint'),
    ('/setup',             'Setup wizard (should be locked post-deployment)'),
    ('/actuator/env',      'Spring Boot actuator environment'),
]

SERVER_DISCLOSURE_HEADERS = [
    'Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version',
    'X-AspNetMvc-Version', 'X-Runtime', 'X-Version',
]


def _discover_http_base_urls(ip: str) -> list:
    active = []
    for port in HTTP_PORTS:
        scheme = 'https' if port in (443, 8443) else 'http'
        url = f'{scheme}://{ip}:{port}'
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            active.append({'url': url, 'port': port, 'scheme': scheme, 'status': r.status_code})
        except Exception:
            pass
    return active


def _check_headers(base_url: str, port: int, response: requests.Response) -> list:
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name.lower() not in headers:
            findings.append({
                'finding_id': f'I3-HDR-{header_name.replace("-", "_").upper()}',
                'title': f'Missing Security Header: {header_name}',
                'url': base_url,
                'port': port,
                'header': header_name,
                'risk_level': meta['severity'],
                'cvss_score': meta['cvss'],
                'description': meta['description'],
                'remediation': f'Add response header: {header_name}: <appropriate-value>',
            })

    return findings


def _check_server_disclosure(base_url: str, port: int, response: requests.Response) -> list:
    findings = []
    for hdr in SERVER_DISCLOSURE_HEADERS:
        val = response.headers.get(hdr)
        if val:
            findings.append({
                'finding_id': f'I3-DISC-{hdr.replace("-", "_").upper()}',
                'title': f'Server Technology Disclosed via {hdr} Header',
                'url': base_url,
                'port': port,
                'header': hdr,
                'value': val,
                'risk_level': 'Medium',
                'cvss_score': 5.3,
                'description': (
                    f'The response header "{hdr}: {val}" discloses the server technology and version. '
                    f'This information aids attackers in identifying known CVEs targeting this software version.'
                ),
            })
    return findings


def _check_cors(base_url: str, port: int, response: requests.Response) -> list:
    findings = []
    acao = response.headers.get('Access-Control-Allow-Origin', '')
    if acao == '*':
        findings.append({
            'finding_id': 'I3-CORS-WILDCARD',
            'title': 'CORS Wildcard Origin Allows Cross-Site Requests',
            'url': base_url,
            'port': port,
            'header': 'Access-Control-Allow-Origin',
            'value': acao,
            'risk_level': 'High',
            'cvss_score': 7.4,
            'description': (
                f'The server at {base_url} returns "Access-Control-Allow-Origin: *", '
                f'allowing any web page on the internet to make authenticated requests to this API '
                f'using a victim\'s browser session. This enables cross-site request forgery (CSRF) '
                f'and data exfiltration via malicious websites.'
            ),
        })
    return findings


def _check_http_methods(base_url: str, port: int) -> list:
    findings = []
    try:
        r = requests.options(base_url, timeout=5, verify=False)
        allowed = r.headers.get('Allow', r.headers.get('Access-Control-Allow-Methods', ''))
        dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allowed.upper()]
        if dangerous:
            findings.append({
                'finding_id': 'I3-METHODS',
                'title': f'Potentially Dangerous HTTP Methods Allowed: {", ".join(dangerous)}',
                'url': base_url,
                'port': port,
                'allowed_methods': allowed,
                'dangerous_methods': dangerous,
                'risk_level': 'Medium',
                'cvss_score': 5.3,
                'description': (
                    f'The server advertises HTTP methods {", ".join(dangerous)} via the Allow header. '
                    f'PUT enables arbitrary file upload; DELETE enables file removal; '
                    f'TRACE enables cross-site tracing (XST) attacks.'
                ),
            })
    except Exception:
        pass
    return findings


def _check_auth_bypass(ip: str, base_url: str, port: int) -> list:
    findings = []
    for path, description in SENSITIVE_ENDPOINTS:
        url = f'{base_url}{path}'
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                body_preview = r.text[:300].replace('\n', ' ')
                cvss = 9.1 if 'admin' in path or 'credential' in path or 'config' in path else 7.5
                findings.append({
                    'finding_id': f'I3-AUTHBYPASS-{path.replace("/", "_").strip("_").upper()}',
                    'title': f'Unauthenticated Access to {path}',
                    'url': url,
                    'port': port,
                    'http_status': r.status_code,
                    'content_type': r.headers.get('Content-Type', 'unknown'),
                    'response_preview': body_preview,
                    'risk_level': 'Critical' if cvss >= 9.0 else 'High',
                    'cvss_score': cvss,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                    'description': (
                        f'The endpoint {path} ({description}) returned HTTP 200 without requiring '
                        f'any authentication. This endpoint may expose sensitive device information '
                        f'or allow unauthorised administrative actions.'
                    ),
                })
        except Exception:
            pass
    return findings


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings = []
    scan_summary = {
        'base_urls_found': [],
        'headers_checked': list(SECURITY_HEADERS.keys()),
        'endpoints_probed': len(SENSITIVE_ENDPOINTS),
        'missing_headers': [],
        'accessible_endpoints': [],
        'cors_issues': [],
        'disclosure_issues': [],
    }

    base_urls = _discover_http_base_urls(ip)
    scan_summary['base_urls_found'] = [e['url'] for e in base_urls]

    if not base_urls:
        return {
            'check_id': 'I3',
            'check_name': 'Insecure Ecosystem Interfaces',
            'owasp_ref': 'OWASP IoT Top 10:2018 — I3',
            'implemented': True,
            'status': 'PASS',
            'severity': 'High',
            'security_score': 100,
            'scan_duration_ms': round((time.time() - t0) * 1000),
            'findings': [],
            'scan_summary': scan_summary,
            'technical_detail': 'No HTTP/HTTPS interfaces found on any probed port. No web attack surface exposed.',
            'risk_explanation': 'Without a web interface, the device has no exposure to web-based attacks.',
            'remediation_steps': ['No action required. If a web interface is added in future, apply all security headers.'],
        }

    for endpoint in base_urls:
        base_url = endpoint['url']
        port     = endpoint['port']
        try:
            r = requests.get(base_url, timeout=5, verify=False)

            hdr_findings  = _check_headers(base_url, port, r)
            disc_findings = _check_server_disclosure(base_url, port, r)
            cors_findings = _check_cors(base_url, port, r)
            meth_findings = _check_http_methods(base_url, port)
            auth_findings = _check_auth_bypass(ip, base_url, port)

            all_findings.extend(hdr_findings + disc_findings + cors_findings + meth_findings + auth_findings)

            scan_summary['missing_headers'].extend([f['header'] for f in hdr_findings])
            scan_summary['disclosure_issues'].extend([f'{f["header"]}: {f["value"]}' for f in disc_findings])
            scan_summary['cors_issues'].extend([base_url] if cors_findings else [])
            scan_summary['accessible_endpoints'].extend([f['url'] for f in auth_findings])

        except Exception:
            pass

    seen_ids = set()
    unique_findings = []
    for f in all_findings:
        if f['finding_id'] not in seen_ids:
            seen_ids.add(f['finding_id'])
            unique_findings.append(f)
    all_findings = unique_findings

    critical = sum(1 for f in all_findings if f.get('risk_level') == 'Critical')
    high     = sum(1 for f in all_findings if f.get('risk_level') == 'High')
    medium   = sum(1 for f in all_findings if f.get('risk_level') == 'Medium')

    status = 'FAIL' if (critical + high) > 0 else ('FAIL' if medium >= 3 else 'PASS')
    security_score = max(0, 100 - critical * 20 - high * 10 - medium * 5)

    return {
        'check_id': 'I3',
        'check_name': 'Insecure Ecosystem Interfaces',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I3',
        'implemented': True,
        'status': status,
        'severity': 'High',
        'security_score': security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings': all_findings,
        'scan_summary': scan_summary,
        'technical_detail': (
            f'Probed HTTP interfaces on ports {HTTP_PORTS}. '
            f'Found {len(base_urls)} active interface(s). '
            f'Checked {len(SECURITY_HEADERS)} security headers, {len(SENSITIVE_ENDPOINTS)} sensitive endpoints, '
            f'CORS configuration, HTTP methods, and server disclosure. '
            f'{len(all_findings)} finding(s): {critical} Critical, {high} High, {medium} Medium.'
        ),
        'risk_explanation': (
            'Web interfaces and REST APIs are the primary attack surface for IoT devices accessible on a LAN. '
            'Missing security headers enable browser-based attacks (XSS, clickjacking, MIME sniffing). '
            'Unauthenticated API endpoints allow direct data extraction and configuration manipulation. '
            'Server version disclosure aids targeted exploit selection. '
            'CORS misconfiguration enables cross-origin attacks that steal device data via the victim\'s browser.'
        ),
        'remediation_steps': [
            'Add all 7 HTTP security headers to every response (Content-Security-Policy, HSTS, X-Frame-Options, etc.)',
            'Require authentication on all API endpoints — reject unauthenticated requests with HTTP 401',
            'Remove or suppress the Server, X-Powered-By, and X-Generator response headers',
            'Restrict CORS to specific trusted origins — never use Access-Control-Allow-Origin: *',
            'Disable HTTP methods not required by the application (PUT, DELETE, TRACE)',
            'Lock down /debug, /env, /setup and similar endpoints completely in production firmware',
            'Use HTTPS for all web interfaces and redirect HTTP to HTTPS',
        ],
    }

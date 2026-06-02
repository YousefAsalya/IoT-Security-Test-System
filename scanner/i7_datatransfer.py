"""
I7 — Insecure Data Transfer and Storage
OWASP IoT Top 10:2018

Analyses the device's communication channels for use of unencrypted
protocols. Checks HTTP vs HTTPS availability, TLS version and certificate
quality, MQTT cleartext vs TLS, and FTP presence.
"""

import ssl
import socket
import time
import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS  = [80, 8080, 8888]
HTTPS_PORTS = [443, 8443]
MQTT_PORT   = 1883
MQTTS_PORT  = 8883
FTP_PORT    = 21

TLS_VERSION_RISK = {
    'SSLv2':   ('Critical', 9.8, 'Completely broken; trivially decryptable'),
    'SSLv3':   ('Critical', 9.8, 'POODLE attack; completely insecure'),
    'TLSv1':   ('High',     7.5, 'TLS 1.0 deprecated (RFC 8996); BEAST/POODLE-TLS attacks'),
    'TLSv1.1': ('High',     7.5, 'TLS 1.1 deprecated (RFC 8996); no AEAD cipher support'),
    'TLSv1.2': ('Info',     0.0, 'TLS 1.2 acceptable with strong cipher suites'),
    'TLSv1.3': ('Info',     0.0, 'TLS 1.3 — current best practice'),
}


def _is_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _analyse_tls(ip: str, port: int) -> dict:
    result = {
        'port': port, 'tls_available': False,
        'version': '', 'cipher': '', 'cipher_bits': 0,
        'cert': {}, 'findings': [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                result['tls_available'] = True
                result['version'] = ssock.version() or 'Unknown'
                cipher_info = ssock.cipher()
                if cipher_info:
                    result['cipher']      = cipher_info[0]
                    result['cipher_bits'] = cipher_info[2] or 0

                der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                if cert_dict:
                    not_after_str  = cert_dict.get('notAfter', '')
                    not_before_str = cert_dict.get('notBefore', '')
                    result['cert']['subject']   = dict(x[0] for x in cert_dict.get('subject', []))
                    result['cert']['issuer']    = dict(x[0] for x in cert_dict.get('issuer', []))
                    result['cert']['not_after'] = not_after_str
                    result['cert']['not_before'] = not_before_str
                    result['cert']['san'] = [
                        v for t, v in cert_dict.get('subjectAltName', [])
                    ]

                    try:
                        not_after = ssl.cert_time_to_seconds(not_after_str)
                        days_left = (not_after - time.time()) / 86400
                        result['cert']['days_to_expiry'] = round(days_left)
                        if days_left < 0:
                            result['findings'].append({
                                'finding_id': f'I7-CERT-EXPIRED-{port}',
                                'title': f'TLS Certificate Expired on Port {port}',
                                'port': port, 'risk_level': 'Critical', 'cvss_score': 7.5,
                                'description': f'Certificate expired {abs(round(days_left))} days ago. Clients may reject the connection.',
                            })
                        elif days_left < 30:
                            result['findings'].append({
                                'finding_id': f'I7-CERT-EXPIRING-{port}',
                                'title': f'TLS Certificate Expires in {round(days_left)} Days',
                                'port': port, 'risk_level': 'Medium', 'cvss_score': 5.3,
                                'description': f'Certificate expires in {round(days_left)} days. Renew before expiry to avoid service disruption.',
                            })
                    except Exception:
                        pass

                    subject = result['cert'].get('subject', {})
                    issuer  = result['cert'].get('issuer', {})
                    if subject.get('commonName') == issuer.get('commonName'):
                        result['cert']['self_signed'] = True
                        result['findings'].append({
                            'finding_id': f'I7-CERT-SELFSIGNED-{port}',
                            'title': f'Self-Signed TLS Certificate on Port {port}',
                            'port': port, 'risk_level': 'Medium', 'cvss_score': 5.9,
                            'description': (
                                'The TLS certificate is self-signed (issuer == subject). '
                                'Browsers and clients will display certificate warnings, '
                                'and users may be trained to bypass security warnings, enabling MITM attacks.'
                            ),
                        })

                ver = result['version']
                version_risk = TLS_VERSION_RISK.get(ver, ('Info', 0.0, 'Unknown TLS version'))
                if version_risk[0] in ('Critical', 'High'):
                    result['findings'].append({
                        'finding_id': f'I7-TLS-WEAK-{port}',
                        'title': f'Weak TLS Version Negotiated: {ver} on Port {port}',
                        'port': port,
                        'tls_version': ver,
                        'risk_level': version_risk[0],
                        'cvss_score': version_risk[1],
                        'description': version_risk[2],
                    })

                if result['cipher_bits'] and result['cipher_bits'] < 128:
                    result['findings'].append({
                        'finding_id': f'I7-CIPHER-WEAK-{port}',
                        'title': f'Weak Cipher Key Length ({result["cipher_bits"]} bits) on Port {port}',
                        'port': port,
                        'cipher': result['cipher'],
                        'bits': result['cipher_bits'],
                        'risk_level': 'High',
                        'cvss_score': 7.4,
                        'description': (
                            f'The negotiated cipher uses only {result["cipher_bits"]}-bit keys, '
                            f'below the recommended minimum of 128 bits.'
                        ),
                    })

    except ssl.SSLError as e:
        result['ssl_error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result


def _check_cleartext_login(ip: str) -> list:
    findings = []
    login_paths = ['/api/login', '/login', '/admin/login', '/api/auth']
    for port in HTTP_PORTS:
        if not _is_open(ip, port):
            continue
        for path in login_paths:
            url = f'http://{ip}:{port}{path}'
            try:
                r = requests.post(
                    url,
                    json={'username': 'probe', 'password': 'probe'},
                    timeout=4, verify=False, allow_redirects=False,
                )
                if r.status_code in (200, 401, 403):
                    findings.append({
                        'finding_id': f'I7-HTTP-LOGIN-{port}',
                        'title': f'Login Endpoint Accessible Over Cleartext HTTP (Port {port})',
                        'url': url,
                        'port': port,
                        'http_status': r.status_code,
                        'risk_level': 'High',
                        'cvss_score': 8.1,
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
                        'description': (
                            f'A login endpoint exists at {url} accessible over plain HTTP. '
                            f'Credentials submitted to this endpoint are transmitted unencrypted '
                            f'and can be captured by any passive observer on the network path.'
                        ),
                    })
                    break
            except Exception:
                pass
    return findings


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings = []
    scan_summary = {
        'http_ports_open': [],
        'https_ports_open': [],
        'mqtt_cleartext_open': False,
        'mqtts_open': False,
        'ftp_open': False,
        'tls_analyses': [],
    }

    for port in HTTP_PORTS:
        if _is_open(ip, port):
            scan_summary['http_ports_open'].append(port)
            all_findings.append({
                'finding_id': f'I7-HTTP-{port}',
                'title': f'Cleartext HTTP Interface on Port {port}',
                'port': port,
                'risk_level': 'High',
                'cvss_score': 5.9,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'description': (
                    f'Port {port} serves HTTP (unencrypted). All traffic — including session tokens '
                    f'and submitted form data — is transmitted in cleartext and readable by any '
                    f'passive observer on the network path (ARP spoofing, passive tap, rogue AP).'
                ),
            })

    for port in HTTPS_PORTS:
        if _is_open(ip, port):
            scan_summary['https_ports_open'].append(port)
            tls = _analyse_tls(ip, port)
            scan_summary['tls_analyses'].append({
                'port': port,
                'version': tls.get('version'),
                'cipher': tls.get('cipher'),
                'cipher_bits': tls.get('cipher_bits'),
                'days_to_expiry': tls.get('cert', {}).get('days_to_expiry'),
            })
            all_findings.extend(tls.get('findings', []))

    mqtt_open  = _is_open(ip, MQTT_PORT)
    mqtts_open = _is_open(ip, MQTTS_PORT)
    scan_summary['mqtt_cleartext_open'] = mqtt_open
    scan_summary['mqtts_open']          = mqtts_open

    if mqtt_open and not mqtts_open:
        all_findings.append({
            'finding_id': 'I7-MQTT-CLEARTEXT',
            'title': 'MQTT Messaging Transmitted in Cleartext (Port 1883, No MQTTS)',
            'port': MQTT_PORT,
            'risk_level': 'High',
            'cvss_score': 7.5,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'description': (
                'MQTT is open on port 1883 (cleartext) without a TLS-secured alternative on port 8883. '
                'All IoT telemetry, sensor readings, and command messages are transmitted unencrypted '
                'and can be intercepted and manipulated by any host on the network.'
            ),
        })
    elif mqtt_open and mqtts_open:
        all_findings.append({
            'finding_id': 'I7-MQTT-DUAL',
            'title': 'Both Cleartext MQTT (1883) and MQTTS (8883) Are Open',
            'port': MQTT_PORT,
            'risk_level': 'Medium',
            'cvss_score': 5.3,
            'description': (
                'Both cleartext MQTT (1883) and encrypted MQTTS (8883) are available. '
                'Clients that connect to port 1883 (even unintentionally) will communicate in cleartext. '
                'Disable port 1883 and enforce exclusive use of port 8883.'
            ),
        })

    ftp_open = _is_open(ip, FTP_PORT)
    scan_summary['ftp_open'] = ftp_open
    if ftp_open:
        all_findings.append({
            'finding_id': 'I7-FTP',
            'title': 'FTP Service Open — Cleartext File Transfer Protocol',
            'port': FTP_PORT,
            'risk_level': 'High',
            'cvss_score': 7.5,
            'description': (
                'FTP transmits all data including filenames, file contents, and login credentials '
                'in cleartext. Use SFTP (SSH-based, port 22) or FTPS (FTP over TLS) instead.'
            ),
        })

    all_findings.extend(_check_cleartext_login(ip))

    http_only = len(scan_summary['http_ports_open']) > 0 and len(scan_summary['https_ports_open']) == 0
    if http_only:
        all_findings.append({
            'finding_id': 'I7-HTTP-ONLY',
            'title': 'No HTTPS Available — Device Has No Encrypted Web Interface',
            'risk_level': 'High',
            'cvss_score': 6.5,
            'description': (
                'The device exposes HTTP web interface(s) but no HTTPS alternative is available. '
                'All web management traffic is unencrypted. An attacker performing ARP spoofing '
                'can silently intercept all credentials and session tokens.'
            ),
        })

    seen = set()
    unique_findings = []
    for f in all_findings:
        if f['finding_id'] not in seen:
            seen.add(f['finding_id'])
            unique_findings.append(f)
    all_findings = unique_findings

    critical = sum(1 for f in all_findings if f.get('risk_level') == 'Critical')
    high     = sum(1 for f in all_findings if f.get('risk_level') == 'High')

    status = 'FAIL' if (critical + high) > 0 else 'PASS'
    security_score = max(0, 100 - critical * 25 - high * 15)

    return {
        'check_id': 'I7',
        'check_name': 'Insecure Data Transfer and Storage',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I7',
        'implemented': True,
        'status': status,
        'severity': 'High',
        'security_score': security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings': all_findings,
        'scan_summary': scan_summary,
        'technical_detail': (
            f'HTTP ports: {scan_summary["http_ports_open"] or "none"}. '
            f'HTTPS ports: {scan_summary["https_ports_open"] or "none"}. '
            f'MQTT cleartext: {"open" if mqtt_open else "closed"}. '
            f'MQTTS: {"open" if mqtts_open else "closed"}. '
            f'FTP: {"open" if ftp_open else "closed"}. '
            f'{len(all_findings)} finding(s) identified.'
        ),
        'risk_explanation': (
            'Unencrypted communications allow passive eavesdropping with no active exploitation required. '
            'On a shared network (Wi-Fi, LAN), an attacker can use ARP spoofing to become a silent MITM '
            'and capture all credentials, session tokens, sensor data, and control commands. '
            'MQTT telemetry transmitted without TLS reveals device state and allows command injection. '
            'TLS 1.0/1.1 are formally deprecated (RFC 8996, 2021) and have known protocol-level weaknesses.'
        ),
        'remediation_steps': [
            'Deploy TLS certificates on all web interfaces — obtain free certificates from Let\'s Encrypt',
            'Redirect HTTP to HTTPS and set HSTS with a long max-age (min. 1 year)',
            'Migrate MQTT to MQTTS (port 8883) using TLS 1.2 or 1.3; disable port 1883',
            'Configure TLS to support only TLS 1.2 and TLS 1.3; disable TLS 1.0, TLS 1.1, SSLv3',
            'Replace FTP with SFTP; if FTP is required, use FTPS with explicit TLS',
            'Use certificate authority-signed certificates, not self-signed, to prevent MITM warnings',
            'Set up certificate expiry monitoring and renew certificates at least 30 days before expiry',
        ],
    }

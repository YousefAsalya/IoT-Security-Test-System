"""
I2 — Insecure Network Services
OWASP IoT Top 10:2018

Performs an active TCP port scan across IoT-relevant ports, grabs service
banners, fingerprints running services, and classifies each by risk level.
Detects legacy protocols, industrial IoT protocols, and unauthenticated
data-store services.
"""

import socket
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

IOT_PORT_REGISTRY = {
    21:    {'service': 'FTP',           'risk': 'High',     'reason': 'Transfers files in cleartext; credentials interceptable by passive sniffing'},
    22:    {'service': 'SSH',           'risk': 'Info',     'reason': 'Encrypted remote access; verify key-based auth is enforced'},
    23:    {'service': 'Telnet',        'risk': 'Critical', 'reason': 'Cleartext remote shell; all commands and credentials visible to network sniffers'},
    25:    {'service': 'SMTP',          'risk': 'Medium',   'reason': 'Email relay; unexpected on IoT devices, frequently abused for spam'},
    53:    {'service': 'DNS',           'risk': 'Medium',   'reason': 'DNS server; unexpected on IoT, potential for DNS amplification abuse'},
    80:    {'service': 'HTTP',          'risk': 'Medium',   'reason': 'Unencrypted web interface; credentials and session tokens transmitted in cleartext'},
    443:   {'service': 'HTTPS',         'risk': 'Info',     'reason': 'Encrypted web interface; verify TLS version and certificate validity'},
    502:   {'service': 'Modbus/TCP',    'risk': 'Critical', 'reason': 'Industrial control protocol with no authentication; allows read/write of sensor/actuator values'},
    554:   {'service': 'RTSP',          'risk': 'High',     'reason': 'Video streaming; often accessible without credentials, exposes live camera feed'},
    1883:  {'service': 'MQTT',          'risk': 'High',     'reason': 'IoT messaging; no authentication by default, any client can subscribe/publish'},
    2222:  {'service': 'SSH-alt',       'risk': 'Info',     'reason': 'SSH on alternate port; verify key-based auth is enforced'},
    4840:  {'service': 'OPC-UA',        'risk': 'High',     'reason': 'Industrial automation protocol; default config may lack authentication'},
    5900:  {'service': 'VNC',           'risk': 'High',     'reason': 'Remote desktop; frequently protected by weak or no password'},
    6379:  {'service': 'Redis',         'risk': 'Critical', 'reason': 'In-memory database with no auth by default; full read/write/exec access'},
    8080:  {'service': 'HTTP-alt',      'risk': 'Medium',   'reason': 'Alternate HTTP port for web admin; same risks as port 80'},
    8443:  {'service': 'HTTPS-alt',     'risk': 'Info',     'reason': 'Alternate HTTPS port; verify TLS configuration'},
    8888:  {'service': 'HTTP-dev',      'risk': 'Medium',   'reason': 'Development/debug HTTP port; often has debug endpoints enabled'},
    9200:  {'service': 'Elasticsearch', 'risk': 'Critical', 'reason': 'Search database; no authentication in older versions, full data access'},
    27017: {'service': 'MongoDB',       'risk': 'Critical', 'reason': 'Document database; no authentication by default in many configurations'},
    47808: {'service': 'BACnet/IP',     'risk': 'Critical', 'reason': 'Building automation protocol; no authentication, allows HVAC/access control manipulation'},
}

BANNER_PROBES = {
    21:    b'',
    22:    b'',
    23:    b'',
    80:    b'HEAD / HTTP/1.0\r\n\r\n',
    443:   b'HEAD / HTTP/1.0\r\n\r\n',
    502:   bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]),
    554:   b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n',
    1883:  bytes([0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x3c, 0x00, 0x00]),
    8080:  b'HEAD / HTTP/1.0\r\n\r\n',
    8888:  b'HEAD / HTTP/1.0\r\n\r\n',
    9200:  b'GET / HTTP/1.0\r\n\r\n',
    27017: bytes([0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00]),
}

RISK_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Info': 3}


def _probe_port(ip: str, port: int, timeout: float = 3.0) -> dict:
    result = {'port': port, 'open': False, 'banner': '', 'error': ''}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return result
        result['open'] = True

        probe = BANNER_PROBES.get(port, b'')
        if probe:
            try:
                s.sendall(probe)
            except Exception:
                pass

        try:
            s.settimeout(2.0)
            raw = s.recv(1024)
            result['banner'] = raw.decode('utf-8', errors='replace').strip()[:300]
        except Exception:
            pass

        s.close()
    except Exception as e:
        result['error'] = str(e)[:60]
    return result


def _fingerprint_service(port: int, banner: str) -> str:
    banner_lower = banner.lower()

    if port in (22, 2222):
        m = re.search(r'ssh-\d+\.\d+-(\S+)', banner, re.IGNORECASE)
        return m.group(0) if m else (banner[:60] or 'SSH')

    if port in (21,):
        m = re.search(r'220[- ](.+)', banner)
        return m.group(1)[:60] if m else (banner[:60] or 'FTP')

    if port in (80, 8080, 8443, 8888, 443):
        server = re.search(r'server:\s*(.+)', banner_lower)
        return server.group(1).strip()[:60] if server else 'HTTP'

    if port == 1883 and banner:
        return 'MQTT broker (responded to CONNECT)'

    if port == 9200 and 'elasticsearch' in banner_lower:
        ver = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        return f'Elasticsearch {ver.group(1)}' if ver else 'Elasticsearch'

    if port == 27017 and banner:
        return 'MongoDB (responded to wire protocol)'

    return banner[:60] if banner else (IOT_PORT_REGISTRY.get(port, {}).get('service', f'port-{port}'))


def run_check(ip: str) -> dict:
    t0 = time.time()
    ports_to_scan = list(IOT_PORT_REGISTRY.keys())

    probe_results = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_port, ip, p): p for p in ports_to_scan}
        for future in as_completed(futures):
            p = futures[future]
            try:
                probe_results[p] = future.result()
            except Exception as e:
                probe_results[p] = {'port': p, 'open': False, 'banner': '', 'error': str(e)}

    open_ports = {p: r for p, r in probe_results.items() if r['open']}
    findings = []

    for port, probe in sorted(open_ports.items()):
        registry = IOT_PORT_REGISTRY.get(port, {'service': f'unknown-{port}', 'risk': 'Medium', 'reason': 'Unregistered port'})
        service_id = _fingerprint_service(port, probe['banner'])

        if registry['risk'] in ('Critical', 'High', 'Medium'):
            findings.append({
                'finding_id': f'I2-PORT-{port}',
                'title': f'{registry["service"]} Detected on Port {port}',
                'port': port,
                'service': service_id,
                'risk_level': registry['risk'],
                'banner': probe['banner'][:200] if probe['banner'] else '(no banner)',
                'cvss_score': {'Critical': 9.8, 'High': 7.5, 'Medium': 5.3, 'Info': 0.0}[registry['risk']],
                'description': registry['reason'],
            })

    findings.sort(key=lambda f: RISK_ORDER.get(f['risk_level'], 99))

    open_summary = [
        f"port {p}/{IOT_PORT_REGISTRY.get(p, {}).get('service', '?')} [{IOT_PORT_REGISTRY.get(p, {}).get('risk', '?')}]"
        for p in sorted(open_ports.keys())
    ]
    critical_count = sum(1 for f in findings if f['risk_level'] == 'Critical')
    high_count     = sum(1 for f in findings if f['risk_level'] == 'High')

    status = 'FAIL' if any(f['risk_level'] in ('Critical', 'High') for f in findings) else 'PASS'
    security_score = max(0, 100 - critical_count * 30 - high_count * 15)

    return {
        'check_id': 'I2',
        'check_name': 'Insecure Network Services',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I2',
        'implemented': True,
        'status': status,
        'severity': 'High',
        'security_score': security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings': findings,
        'scan_summary': {
            'ports_scanned': len(ports_to_scan),
            'ports_open': len(open_ports),
            'open_services': open_summary,
            'critical_findings': critical_count,
            'high_findings': high_count,
        },
        'technical_detail': (
            f'Scanned {len(ports_to_scan)} IoT-relevant TCP ports. '
            f'Found {len(open_ports)} open port(s): {", ".join(str(p) for p in sorted(open_ports.keys())) or "none"}. '
            f'{len(findings)} risk finding(s) identified ({critical_count} Critical, {high_count} High).'
        ),
        'risk_explanation': (
            'Every open port is a potential attack entry point. Legacy protocols such as Telnet and FTP '
            'transmit all data — including credentials — in cleartext readable by any passive network observer. '
            'Industrial protocols (Modbus, BACnet) carry no authentication and allow direct manipulation of '
            'physical actuators. Unauthenticated data stores (Redis, Elasticsearch, MongoDB) grant full data '
            'access without any credential. The principle of least exposure requires disabling every service '
            'not strictly required for the device\'s function.'
        ),
        'remediation_steps': [
            'Disable all network services not required for the device\'s operational function',
            'Replace Telnet with SSH; configure SSH to use key-based authentication only',
            'Replace FTP with SFTP (runs over SSH) or FTPS',
            'Restrict Modbus/BACnet/OPC-UA access to authorised engineering workstations via firewall ACLs',
            'Configure Redis, MongoDB, Elasticsearch to require authentication and bind to localhost',
            'Implement a host-based firewall (iptables/nftables) as a secondary defence layer',
            'Conduct regular port scans as part of a change management process',
        ],
    }

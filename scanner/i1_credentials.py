"""
I1 — Weak, Guessable, or Hardcoded Passwords
OWASP IoT Top 10:2018

Tests SSH, HTTP login endpoints, and MQTT brokers for acceptance of
known IoT default credentials. Stops at first confirmed hit per protocol
to avoid triggering account lockout mechanisms.
"""

import socket
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import telnetlib
    TELNETLIB_AVAILABLE = True
except ImportError:
    TELNETLIB_AVAILABLE = False

try:
    import paho.mqtt.client as mqtt_client
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False

IOT_DEFAULT_CREDENTIALS = [
    ('admin',         'admin'),
    ('admin',         'password'),
    ('admin',         '1234'),
    ('admin',         '12345'),
    ('admin',         '123456'),
    ('admin',         ''),
    ('root',          'root'),
    ('root',          'toor'),
    ('root',          'password'),
    ('root',          ''),
    ('user',          'user'),
    ('guest',         'guest'),
    ('pi',            'raspberry'),
    ('support',       'support'),
    ('administrator', 'administrator'),
    ('admin',         'admin123'),
    ('ubnt',          'ubnt'),
]

SSH_PORTS   = [22, 2222]
HTTP_PORTS  = [80, 8080, 8888]
MQTT_PORT   = 1883


def _is_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _test_ssh(ip: str, port: int) -> dict:
    result = {'port': port, 'open': _is_open(ip, port), 'findings': [], 'tested': 0, 'banner': ''}

    if not result['open']:
        return result

    if not PARAMIKO_AVAILABLE:
        result['error'] = 'paramiko not installed — pip install paramiko'
        return result

    try:
        transport = paramiko.Transport((ip, port))
        transport.connect()
        result['banner'] = str(transport.remote_version)
        transport.close()
    except Exception as e:
        result['banner'] = str(e)[:80]

    for username, password in IOT_DEFAULT_CREDENTIALS:
        result['tested'] += 1
        t0 = time.time()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port,
                username=username, password=password,
                timeout=5, banner_timeout=5, auth_timeout=5,
                look_for_keys=False, allow_agent=False,
            )
            elapsed = round(time.time() - t0, 2)
            command_output = ''
            try:
                _, stdout, _ = client.exec_command('id', timeout=3)
                command_output = stdout.read().decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            client.close()
            result['findings'].append({
                'finding_id': f'I1-SSH-{port}',
                'title': f'Default SSH Credential Accepted on Port {port}',
                'protocol': 'SSH',
                'port': port,
                'credential': f'{username} / {password if password else "(empty)"}',
                'command_output': command_output,
                'time_to_crack_s': elapsed,
                'cvss_score': 9.8,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'description': (
                    f'The SSH service on port {port} accepted the default credential '
                    f'"{username}"/"{password if password else "(empty)"}". '
                    f'An attacker with network access can gain full shell access without any prior knowledge.'
                ),
            })
            break
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break

    return result


def _test_http_login(ip: str) -> dict:
    result = {'findings': [], 'tested': 0, 'endpoints_probed': []}

    login_paths = [
        '/api/login',
        '/login',
        '/api/auth',
        '/admin/login',
        '/user/login',
    ]

    active_endpoints = []
    for port in HTTP_PORTS:
        for path in login_paths:
            url = f'http://{ip}:{port}{path}'
            try:
                r = requests.options(url, timeout=4, verify=False, allow_redirects=False)
                if r.status_code < 500:
                    active_endpoints.append({'url': url, 'port': port, 'path': path})
                    result['endpoints_probed'].append(url)
            except Exception:
                pass

    for endpoint in active_endpoints:
        url = endpoint['url']
        for username, password in IOT_DEFAULT_CREDENTIALS:
            result['tested'] += 1
            try:
                r = requests.post(
                    url,
                    json={'username': username, 'password': password},
                    timeout=5, verify=False, allow_redirects=False,
                )
                body = r.text.lower()
                success = (
                    r.status_code == 200
                    and any(k in body for k in ['token', 'session', 'welcome', 'success', 'dashboard'])
                    and not any(k in body for k in ['invalid', 'incorrect', 'failed', 'error', 'wrong'])
                )
                if success:
                    result['findings'].append({
                        'finding_id': f'I1-HTTP-{endpoint["port"]}',
                        'title': f'Default HTTP Credential Accepted at {url}',
                        'protocol': 'HTTP',
                        'port': endpoint['port'],
                        'url': url,
                        'credential': f'{username} / {password if password else "(empty)"}',
                        'http_status': r.status_code,
                        'response_snippet': r.text[:200],
                        'cvss_score': 9.1,
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        'description': (
                            f'The HTTP login endpoint at {url} accepted the default credential '
                            f'"{username}"/"{password if password else "(empty)"}". '
                            f'The response contained a session token or success indicator.'
                        ),
                    })
                    break
            except Exception:
                continue
        if result['findings']:
            break

    return result


def _test_mqtt(ip: str) -> dict:
    result = {
        'port': MQTT_PORT,
        'open': _is_open(ip, MQTT_PORT),
        'findings': [],
        'anonymous_allowed': False,
    }

    if not result['open']:
        return result

    if not PAHO_AVAILABLE:
        result['error'] = 'paho-mqtt not installed — pip install paho-mqtt'
        result['anonymous_allowed'] = _test_mqtt_raw(ip)
        if result['anonymous_allowed']:
            result['findings'].append(_mqtt_anonymous_finding(ip))
        return result

    connect_result = {'code': -1}

    def on_connect(client, userdata, flags, rc):
        connect_result['code'] = rc

    client = mqtt_client.Client(client_id='iot-scanner-probe', clean_session=True)
    client.on_connect = on_connect
    client.username_pw_set(None, None)

    try:
        client.connect(ip, MQTT_PORT, keepalive=5)
        client.loop_start()
        deadline = time.time() + 5
        while time.time() < deadline and connect_result['code'] == -1:
            time.sleep(0.1)
        client.loop_stop()
        client.disconnect()

        if connect_result['code'] == 0:
            result['anonymous_allowed'] = True
            result['findings'].append(_mqtt_anonymous_finding(ip))
    except Exception:
        result['anonymous_allowed'] = _test_mqtt_raw(ip)
        if result['anonymous_allowed']:
            result['findings'].append(_mqtt_anonymous_finding(ip))

    if not result['anonymous_allowed']:
        for username, password in IOT_DEFAULT_CREDENTIALS:
            client2 = mqtt_client.Client(client_id='iot-scanner-probe2', clean_session=True)
            c2result = {'code': -1}
            client2.on_connect = lambda cl, ud, fl, rc: c2result.update({'code': rc})
            client2.username_pw_set(username, password)
            try:
                client2.connect(ip, MQTT_PORT, keepalive=5)
                client2.loop_start()
                deadline = time.time() + 3
                while time.time() < deadline and c2result['code'] == -1:
                    time.sleep(0.1)
                client2.loop_stop()
                client2.disconnect()
                if c2result['code'] == 0:
                    result['findings'].append({
                        'finding_id': 'I1-MQTT-CRED',
                        'title': 'Default MQTT Credential Accepted',
                        'protocol': 'MQTT',
                        'port': MQTT_PORT,
                        'credential': f'{username} / {password if password else "(empty)"}',
                        'cvss_score': 8.6,
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                        'description': (
                            f'The MQTT broker accepted the default credential '
                            f'"{username}"/"{password if password else "(empty)"}". '
                            f'An attacker can subscribe to all topics and intercept device telemetry.'
                        ),
                    })
                    break
            except Exception:
                continue

    return result


def _test_mqtt_raw(ip: str) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, MQTT_PORT))
        connect_pkt = bytes([
            0x10, 0x12,
            0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
            0x04, 0x02, 0x00, 0x3c,
            0x00, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        ])
        s.send(connect_pkt)
        resp = s.recv(4)
        s.close()
        return len(resp) >= 4 and resp[3] == 0x00
    except Exception:
        return False


def _mqtt_anonymous_finding(ip: str) -> dict:
    return {
        'finding_id': 'I1-MQTT-ANON',
        'title': 'MQTT Broker Accepts Anonymous Connections',
        'protocol': 'MQTT',
        'port': MQTT_PORT,
        'credential': '(none — anonymous access)',
        'cvss_score': 9.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'description': (
            f'The MQTT broker on {ip}:{MQTT_PORT} accepts connections without any credentials. '
            f'Any client on the network can subscribe to all topics (#) and read device telemetry, '
            f'or publish commands to actuator topics, with no authentication required.'
        ),
    }


def run_check(ip: str) -> dict:
    t0 = time.time()
    all_findings = []
    scan_summary = {
        'ssh_ports_probed': SSH_PORTS,
        'http_ports_probed': HTTP_PORTS,
        'mqtt_port_probed': MQTT_PORT,
        'credentials_in_list': len(IOT_DEFAULT_CREDENTIALS),
        'ssh_results': '',
        'http_endpoints_probed': [],
        'mqtt_open': False,
        'mqtt_anonymous': False,
    }

    ssh_cracked: list[str] = []
    for port in SSH_PORTS:
        ssh_r = _test_ssh(ip, port)
        for finding in ssh_r.get('findings', []):
            ssh_cracked.append(finding['credential'])
        all_findings.extend(ssh_r.get('findings', []))

    scan_summary['ssh_results'] = (
        ', '.join(ssh_cracked)
        if ssh_cracked
        else f'No default credentials accepted on SSH ports {SSH_PORTS}'
    )

    http_r = _test_http_login(ip)
    scan_summary['http_endpoints_probed'] = http_r.get('endpoints_probed', [])
    all_findings.extend(http_r.get('findings', []))

    mqtt_r = _test_mqtt(ip)
    scan_summary['mqtt_open'] = mqtt_r['open']
    scan_summary['mqtt_anonymous'] = mqtt_r.get('anonymous_allowed', False)
    all_findings.extend(mqtt_r.get('findings', []))

    status = 'FAIL' if all_findings else 'PASS'
    max_cvss = max((f.get('cvss_score', 0) for f in all_findings), default=0)
    security_score = 100 if not all_findings else max(0, round(100 - max_cvss * 10))

    return {
        'check_id': 'I1',
        'check_name': 'Weak, Guessable, or Hardcoded Passwords',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I1',
        'implemented': True,
        'status': status,
        'severity': 'Critical',
        'security_score': security_score,
        'scan_duration_ms': round((time.time() - t0) * 1000),
        'findings': all_findings,
        'scan_summary': scan_summary,
        'technical_detail': (
            f'Probed SSH on ports {SSH_PORTS}, HTTP login on ports {HTTP_PORTS}, '
            f'and MQTT on port {MQTT_PORT} using {len(IOT_DEFAULT_CREDENTIALS)} IoT default credential pairs. '
            + (f'Found {len(all_findings)} credential vulnerability(ies).' if all_findings
               else 'No default credentials accepted across all tested protocols.')
        ),
        'risk_explanation': (
            'Default and hardcoded credentials are the primary attack vector for IoT device compromise. '
            'The Mirai botnet (2016) compromised over 600,000 devices using only default credential lists. '
            'A successful login grants the attacker the same access level as the legitimate administrator, '
            'enabling data exfiltration, device reprogramming, lateral network movement, and botnet enrollment.'
        ),
        'remediation_steps': [
            'Change all default credentials immediately upon device deployment',
            'Enforce a minimum password complexity policy (≥12 chars, mixed case, digits, symbols)',
            'Disable Telnet and replace with SSH using key-based authentication',
            'Configure MQTT authentication with per-device credentials and TLS',
            'Implement account lockout after 5 failed login attempts',
            'Consider certificate-based mutual authentication for device-to-broker MQTT connections',
        ],
    }

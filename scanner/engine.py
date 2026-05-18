import json
import socket
import platform
import subprocess
import ipaddress
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from database import save_scan
from .i1_credentials  import run_check as check_i1
from .i2_services     import run_check as check_i2
from .i3_interfaces   import run_check as check_i3
from .i7_datatransfer import run_check as check_i7

IMPLEMENTED_CHECKS = [check_i1, check_i2, check_i3, check_i7]

NOT_IMPLEMENTED = [
    {
        'check_id': 'I4',
        'check_name': 'Lack of Secure Update Mechanism',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I4',
        'implemented': False,
        'status': 'N/A',
        'severity': 'High',
        'exclusion_reason': (
            'Requires firmware binary access and knowledge of the device-specific update protocol. '
            'Surface-level HTTP endpoint probing cannot confirm absence of firmware signature verification. '
            'See REQUIREMENTS.md §2 for full rationale.'
        ),
    },
    {
        'check_id': 'I5',
        'check_name': 'Use of Insecure or Outdated Components',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I5',
        'implemented': False,
        'status': 'N/A',
        'severity': 'High',
        'exclusion_reason': (
            'Version-to-CVE mapping requires an up-to-date vulnerability database and produces '
            'unreliable results when services suppress version banners. Adequately addressed by '
            'dedicated tools (OpenVAS, Trivy). Banner data from I2 provides the necessary input for manual CVE lookup.'
        ),
    },
    {
        'check_id': 'I6',
        'check_name': 'Insufficient Privacy Protection',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I6',
        'implemented': False,
        'status': 'N/A',
        'severity': 'High',
        'exclusion_reason': (
            'Full privacy assessment requires device-specific threat modelling and regulatory context. '
            'API data exposure is already detected by I3 (authentication bypass / endpoint probing). '
            'Keyword-based scanning produces high false-positive rates. See REQUIREMENTS.md §2.'
        ),
    },
    {
        'check_id': 'I8',
        'check_name': 'Lack of Device Management',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I8',
        'implemented': False,
        'status': 'N/A',
        'severity': 'Medium',
        'exclusion_reason': (
            'Network-observable aspects (unauthenticated management endpoints, Telnet) are already '
            'covered with greater depth by I1 and I3. Broader management security issues (audit logging, '
            'remote wipe, credential rotation) are not network-observable. See REQUIREMENTS.md §2.'
        ),
    },
    {
        'check_id': 'I9',
        'check_name': 'Insecure Default Settings',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I9',
        'implemented': False,
        'status': 'N/A',
        'severity': 'Medium',
        'exclusion_reason': (
            'The security-impactful default settings (default credentials, open dangerous services, '
            'missing encryption) are captured with full depth by I1, I2, and I7. Remaining indicators '
            'are too device-specific for a general-purpose scanner. See REQUIREMENTS.md §2.'
        ),
    },
    {
        'check_id': 'I10',
        'check_name': 'Lack of Physical Hardening',
        'owasp_ref': 'OWASP IoT Top 10:2018 — I10',
        'implemented': False,
        'status': 'N/A',
        'severity': 'Low',
        'exclusion_reason': (
            'Physical hardening (JTAG/UART interfaces, tamper-evident seals, secure boot) is not '
            'assessable over a TCP/IP network. Requires hardware access and specialised tools. '
            'See REQUIREMENTS.md §2 for full rationale.'
        ),
    },
]


def _check_device_reachable(ip: str):
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '2', '-w', '1000', ip]
        else:
            cmd = ['ping', '-c', '2', ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if result.returncode == 0:
            return True, 'ICMP ping successful'
    except Exception:
        pass

    for port in [80, 443, 22, 23, 8080, 8888, 1883, 2222, 21]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True, f'TCP port {port} responded'
            s.close()
        except Exception:
            pass

    return False, 'Device did not respond to any probe'


def run_scan(ip: str, device_name: str = 'Unknown Device') -> dict:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'error': f'Invalid IP address: {ip}. Example: 192.168.1.1'}

    reachable, reach_method = _check_device_reachable(ip)
    if not reachable:
        return {
            'error': (
                f'Device {ip} is not reachable. '
                f'Verify the IP is correct, the device is powered on and on the same network, '
                f'and no firewall is blocking all traffic to this host.'
            ),
            'device_ip': ip,
            'reachable': False,
        }

    print(f'[+] {ip} reachable via {reach_method}')

    implemented_results = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(fn, ip): fn for fn in IMPLEMENTED_CHECKS}
        for future in as_completed(futures):
            fn = futures[future]
            try:
                implemented_results[fn] = future.result()
            except Exception as e:
                implemented_results[fn] = {
                    'check_id': 'ERR',
                    'check_name': fn.__name__,
                    'owasp_ref': 'N/A',
                    'implemented': True,
                    'status': 'ERROR',
                    'severity': 'Unknown',
                    'security_score': 0,
                    'scan_duration_ms': 0,
                    'findings': [],
                    'scan_summary': {},
                    'technical_detail': f'Check raised an exception: {e}',
                    'risk_explanation': '',
                    'remediation_steps': ['Re-run the scan. Check server logs for details.'],
                }

    ordered_implemented = [implemented_results[fn] for fn in IMPLEMENTED_CHECKS]
    all_checks = ordered_implemented + NOT_IMPLEMENTED

    passed    = sum(1 for r in ordered_implemented if r.get('status') == 'PASS')
    failed    = sum(1 for r in ordered_implemented if r.get('status') == 'FAIL')
    total     = len(IMPLEMENTED_CHECKS)
    pct_score = round((passed / total) * 100) if total > 0 else 0

    scan_date    = datetime.now(timezone.utc).isoformat()
    results_json = json.dumps(all_checks)
    scan_id      = save_scan(ip, device_name, pct_score, results_json)

    return {
        'id':             scan_id,
        'device_ip':      ip,
        'device_name':    device_name,
        'scan_date':      scan_date,
        'reach_method':   reach_method,
        'implemented_count': total,
        'passed':         passed,
        'failed':         failed,
        'security_score': pct_score,
        'total_score':    pct_score,
        'checks':         all_checks,
    }

"""
Network Discovery
Scans the local subnet (or a user-supplied CIDR) for reachable hosts,
identifies open IoT-relevant ports, and provides a lightweight service
fingerprint so the user can pick a target before running a full scan.

This module is intentionally separate from the OWASP check engine —
it is a pre-scan utility, not a security assessment.
"""

import ipaddress
import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ports probed during discovery (fast knock only — no banner grab)
DISCOVERY_PORTS = [22, 23, 80, 443, 1883, 8080, 8443, 8888, 2222, 5900]

# Maps open ports to a human-readable device type hint
DEVICE_TYPE_HINTS = {
    frozenset([1883]):              ('MQTT Broker',        'IoT gateway or message broker'),
    frozenset([22, 1883]):          ('IoT Gateway',        'Linux-based IoT gateway with SSH and MQTT'),
    frozenset([80]):                ('Web Device',         'Device with HTTP management interface'),
    frozenset([80, 443]):           ('Web Device (TLS)',   'Device with HTTP and HTTPS interface'),
    frozenset([22]):                ('Linux Device',       'Linux-based device with SSH'),
    frozenset([23]):                ('Legacy Device',      'Device exposing Telnet — likely legacy firmware'),
    frozenset([5900]):              ('VNC Device',         'Device with VNC remote desktop'),
    frozenset([80, 8080]):          ('Router / AP',        'Consumer router or access point'),
    frozenset([8080]):              ('Alt-HTTP Device',    'Device using non-standard HTTP port'),
    frozenset([8888]):              ('Dev Device',         'Device with development/debug HTTP port'),
    frozenset([22, 80]):            ('Managed Device',     'Network device with SSH and web UI'),
    frozenset([22, 80, 443]):       ('Managed Device',     'Network device with SSH and HTTPS web UI'),
}


def _get_local_cidr() -> str:
    """Best-effort detection of the local /24 subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit('.', 1)
        return f'{parts[0]}.0/24'
    except Exception:
        return '192.168.1.0/24'


def _is_port_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _probe_host(ip: str) -> dict | None:
    """
    Probe a single host: check reachability on discovery ports.
    Returns None if the host does not respond on any port.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=len(DISCOVERY_PORTS)) as pool:
        futures = {pool.submit(_is_port_open, ip, p): p for p in DISCOVERY_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    if not open_ports:
        return None

    open_ports.sort()
    device_type, description = _estimate_device_type(open_ports)

    return {
        'ip':          ip,
        'open_ports':  open_ports,
        'device_type': device_type,
        'description': description,
    }


def _estimate_device_type(open_ports: list) -> tuple[str, str]:
    port_set = frozenset(open_ports)

    # Exact match first
    if port_set in DEVICE_TYPE_HINTS:
        return DEVICE_TYPE_HINTS[port_set]

    # Subset match — find the hint whose key is the largest subset of open_ports
    best_key = frozenset()
    for key in DEVICE_TYPE_HINTS:
        if key.issubset(port_set) and len(key) > len(best_key):
            best_key = key

    if best_key:
        return DEVICE_TYPE_HINTS[best_key]

    return ('Unknown Device', f'Open ports: {", ".join(str(p) for p in open_ports)}')


def discover_devices(cidr: str | None = None) -> dict:
    """
    Main entry point — called by app.py's /api/discover endpoint.

    Args:
        cidr: Optional CIDR string (e.g. '192.168.1.0/24').
              If None, the local /24 subnet is auto-detected.

    Returns:
        {
            'cidr':    str,
            'scanned': int,
            'found':   int,
            'devices': [ { ip, open_ports, device_type, description }, ... ]
        }
    """
    if cidr:
        cidr = cidr.strip()
        # Basic sanity — accept bare IPs and add /24
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cidr):
            cidr = cidr.rsplit('.', 1)[0] + '.0/24'
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return {'error': f'Invalid CIDR block: {cidr!r}. Example: 192.168.1.0/24'}

        # Cap at /16 to avoid accidental internet-wide scans
        if network.prefixlen < 16:
            return {'error': 'CIDR prefix must be /16 or smaller (e.g. 192.168.0.0/16). Wider ranges are not supported.'}
    else:
        cidr = _get_local_cidr()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return {'error': f'Could not determine local subnet (got {cidr!r}).'}

    host_ips = [str(ip) for ip in network.hosts()]

    devices = []
    # Limit concurrency to avoid overwhelming the local network stack
    max_workers = min(50, len(host_ips))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_host, ip): ip for ip in host_ips}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    devices.append(result)
            except Exception:
                pass

    devices.sort(key=lambda d: list(map(int, d['ip'].split('.'))))

    return {
        'cidr':    cidr,
        'scanned': len(host_ips),
        'found':   len(devices),
        'devices': devices,
    }

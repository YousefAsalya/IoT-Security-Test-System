"""
Deliberately Vulnerable IoT Device API
Test environment component — DO NOT deploy in production.

Simulates a poorly secured IoT gateway web interface with the following
intentional vulnerabilities for I1, I3, and I7 scanner testing:
  - No HTTP security headers
  - Server version disclosure
  - Unauthenticated admin panel
  - Unauthenticated /api/config returning plaintext credentials
  - Default credentials accepted at /api/login
  - CORS wildcard
  - Sensitive debug endpoint
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.after_request
def add_vulnerable_headers(response):
    response.headers['Server'] = 'IoT-Gateway/1.0.2 Python/3.11 Flask/2.3'
    response.headers['X-Powered-By'] = 'ESP32-DevKit-v1'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@app.route('/')
def index():
    return jsonify({
        'device': 'IoT Gateway v1.0.2',
        'status': 'online',
        'endpoints': ['/api/login', '/api/config', '/api/status', '/api/debug', '/admin'],
    })


@app.route('/admin')
def admin_panel():
    return '''
    <html>
    <head><title>IoT Gateway Admin</title></head>
    <body>
    <h1>IoT Gateway — Administration Panel</h1>
    <p>Device: IoT-Gateway-001</p>
    <p>Firmware: v1.0.2 (debug build)</p>
    <form method="post" action="/admin/reboot">
        <button type="submit">Reboot Device</button>
    </form>
    <form method="post" action="/admin/factory-reset">
        <button type="submit">Factory Reset</button>
    </form>
    </body>
    </html>
    '''


@app.route('/api/config')
def get_config():
    return jsonify({
        'device_id':      'iot-gateway-001',
        'wifi_ssid':      'HomeNetwork_2G',
        'wifi_password':  'supersecret123',
        'mqtt_broker':    '192.168.1.100',
        'mqtt_user':      'device',
        'mqtt_password':  'device_pass_2024',
        'admin_user':     'admin',
        'admin_password': 'admin',
        'api_key':        'sk-iot-2024-f8a3b1c9d2e7',
        'firmware':       'v1.0.2',
        'debug_enabled':  True,
    })


@app.route('/api/status')
def get_status():
    return jsonify({
        'device':       'iot-gateway-001',
        'uptime_s':     48372,
        'temperature':  42.7,
        'cpu_load':     0.23,
        'free_mem_kb':  18432,
        'firmware':     'v1.0.2 (debug build)',
        'debug_port':   9999,
        'internal_ip':  '172.16.0.1',
        'mac':          'AA:BB:CC:DD:EE:FF',
    })


@app.route('/api/debug')
def debug_info():
    import os, sys
    return jsonify({
        'python':    sys.version,
        'env':       {k: v for k, v in os.environ.items() if 'SECRET' not in k.upper()},
        'debug_key': 'dev-only-key-do-not-expose',
        'db_uri':    'sqlite:///iot.db',
        'jwt_secret': 'change-me-in-production',
    })


@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', '')).strip()

    USERS = {
        'admin':     'admin',
        'root':      'toor',
        'user':      'user',
        'support':   'support',
        'guest':     'guest',
        'pi':        'raspberry',
    }

    if username in USERS and USERS[username] == password:
        return jsonify({
            'status':  'success',
            'token':   'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.',
            'user':    username,
            'role':    'admin' if username in ('admin', 'root') else 'user',
            'welcome': f'Welcome {username}',
        })

    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


@app.route('/api/users')
def list_users():
    return jsonify([
        {'id': 1, 'username': 'admin',   'role': 'admin',  'password_hash': 'YWRtaW4='},
        {'id': 2, 'username': 'support', 'role': 'user',   'password_hash': 'c3VwcG9ydA=='},
        {'id': 3, 'username': 'guest',   'role': 'viewer', 'password_hash': 'Z3Vlc3Q='},
    ])


@app.route('/setup')
def setup():
    return '''
    <html><head><title>Device Setup</title></head>
    <body><h1>Initial Device Setup</h1>
    <p>This setup page is accessible post-deployment.</p></body></html>
    '''


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)

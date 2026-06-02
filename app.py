from flask import Flask, jsonify, request, render_template
from database import init_db, get_all_scans, get_scan_by_id, delete_scan
from scanner import run_scan
from scanner.discovery import discover_devices
import json

app = Flask(__name__)


@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    return response


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/discover', methods=['GET'])
def discover_network():
    cidr = request.args.get('cidr', '').strip() or None
    try:
        result = discover_devices(cidr)
        status_code = 400 if result.get('error') else 200
        return jsonify(result), status_code
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    except Exception as error:
        print(f'Discovery error: {error}')
        return jsonify({'error': f'Device discovery failed: {str(error)}'}), 500


@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def start_scan():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json(silent=True)
    if not data or 'ip' not in data:
        return jsonify({'error': 'Missing "ip" field in request body'}), 400

    device_ip   = str(data['ip']).strip()
    device_name = str(data.get('device_name', 'Unknown Device')).strip() or 'Unknown Device'

    if not device_ip:
        return jsonify({'error': 'IP address cannot be empty'}), 400

    try:
        result = run_scan(device_ip, device_name)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        print(f'Scan error: {e}')
        return jsonify({'error': f'Scan failed: {e}'}), 500


@app.route('/api/scans', methods=['GET'])
def list_scans():
    return jsonify(get_all_scans()), 200


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return jsonify({'error': f'Scan ID {scan_id} not found'}), 404
    try:
        scan['checks'] = json.loads(scan['results_json'])
        del scan['results_json']
    except Exception:
        scan['checks'] = []
    return jsonify(scan), 200


@app.route('/api/scan/<int:scan_id>', methods=['DELETE'])
def remove_scan(scan_id):
    if delete_scan(scan_id):
        return jsonify({'message': f'Scan {scan_id} deleted'}), 200
    return jsonify({'error': f'Scan {scan_id} not found'}), 404


if __name__ == '__main__':
    init_db()
    print('IoT Security Tester starting...')
    print('Open http://localhost:8080')
    app.run(debug=False, host='0.0.0.0', port=8080)

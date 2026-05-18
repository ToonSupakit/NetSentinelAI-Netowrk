from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from app.db import get_device_status, get_anomaly_history, get_analytics
from sqlalchemy import text
from netmiko import ConnectHandler
import yaml
import os
import logging
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

with open('config/config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

with open('config/devices.yaml', 'r', encoding='utf-8') as f:
    devices_config = yaml.safe_load(f)

# Device credentials จาก .env
DEFAULT_USERNAME = os.getenv('DEVICE_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('DEVICE_PASSWORD', 'admin')
DEFAULT_SECRET   = os.getenv('DEVICE_SECRET', 'admin')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'netsentinel-secret')
socketio = SocketIO(app, cors_allowed_origins="*")

def get_device_by_name(name):
    for d in devices_config['devices']:
        if d['name'] == name:
            return d
    return None

def get_device_conn_params(device):
    """สร้าง connection params โดยใช้ credentials จาก .env เป็น default"""
    return {
        'device_type': device['device_type'],
        'host'       : device['host'],
        'username'   : device.get('username') or DEFAULT_USERNAME,
        'password'   : device.get('password') or DEFAULT_PASSWORD,
        'secret'     : device.get('secret') or DEFAULT_SECRET,
    }

# ── Routes ───────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    try:
        from app.db import engine
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({'status': 'ok', 'db': 'connected'})
    except Exception as e:
        return jsonify({'status': 'error', 'db': str(e)}), 500

@app.route('/api/status')
def api_status():
    rows = get_device_status()
    data = []
    for row in rows:
        data.append({
            'device'      : row[0],
            'interface'   : row[1],
            'ip'          : row[2],
            'status'      : row[3],
            'protocol'    : row[4],
            'network_load': row[5],
            'rxload'      : row[6],
            'reliability' : row[7],
            'label'       : row[8],
            'collected_at': str(row[9])
        })
    return jsonify(data)

@app.route('/api/anomalies')
def api_anomalies():
    rows = get_anomaly_history(limit=50)
    data = []
    for row in rows:
        data.append({
            'predicted_at' : str(row[0]),
            'device'       : row[1],
            'interface'    : row[2],
            'label'        : row[3],
            'confidence'   : row[4],
            'is_fixed'     : row[5],
            'status'       : row[6],
            'protocol'     : row[7],
            'network_load' : row[8],
            'rxload'       : row[9],
            'detection_source': row[10] if len(row) > 10 else None,
        })
    return jsonify(data)

@app.route('/api/analytics')
def api_analytics():
    data = get_analytics()
    return jsonify({
        'summary'        : list(data['summary']),
        'today'          : list(data['today']),
        'fix_rate'       : list(data['fix_rate']),
        'uptime'         : [list(r) for r in data['uptime']],
        'top_devices'    : [list(r) for r in data['top_devices']],
        'top_interfaces' : [list(r) for r in data['top_interfaces']],
        'traffic_trend'  : [list(r) for r in data['traffic_trend']],
        'anomaly_by_type': [list(r) for r in data['anomaly_by_type']]
    })

@app.route('/api/traffic')
def api_traffic():
    from app.db import engine
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT device_name, 'ALL' as interface_name,
                   MAX(network_load) as avg_tx,
                   MAX(rxload)       as avg_rx,
                   DATE_FORMAT(MIN(collected_at), '%H:%i') as time_label
            FROM interface_logs
            WHERE collected_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY device_name,
                     DATE_FORMAT(collected_at, '%Y-%m-%d %H:%i')
            ORDER BY MIN(collected_at) DESC
            LIMIT 1000
        """)).fetchall()
    data = [{'device': r[0], 'interface': r[1],
              'tx': float(r[2]), 'rx': float(r[3]),
              'time': r[4]} for r in rows]
    return jsonify(data)

# ── Fix Now (POST only) ──────────────────────────────────
@app.route('/api/fix/<device_name>/<path:intf>', methods=['POST'])
def api_fix(device_name, intf):
    device = get_device_by_name(device_name)
    if not device:
        return jsonify({'success': False, 'message': 'Device not found'})
    try:
        conn_params = get_device_conn_params(device)
        with ConnectHandler(**conn_params) as net:
            net.enable()
            output = net.send_config_set([
                f"interface {intf}",
                "no shutdown"
            ])
        log.info(f"Fixed: {device_name} — {intf}")
        return jsonify({'success': True, 'output': output})
    except Exception as e:
        log.error(f"Fix failed: {device_name} — {intf}: {e}")
        return jsonify({'success': False, 'message': str(e)})

# ── Rate Limit (POST only) ───────────────────────────────
@app.route('/api/ratelimit/<device_name>/<path:intf>', methods=['POST'])
def api_ratelimit(device_name, intf):
    device = get_device_by_name(device_name)
    if not device:
        return jsonify({'success': False, 'message': 'Device not found'})
    try:
        conn_params = get_device_conn_params(device)
        with ConnectHandler(**conn_params) as net:
            net.enable()
            output = net.send_config_set([
                f"interface {intf}",
                "rate-limit input  50000000 8000 8000 conform-action transmit exceed-action drop",
                "rate-limit output 50000000 8000 8000 conform-action transmit exceed-action drop"
            ])
        log.info(f"Rate limited: {device_name} — {intf}")
        return jsonify({'success': True, 'output': output})
    except Exception as e:
        log.error(f"Rate limit failed: {device_name} — {intf}: {e}")
        return jsonify({'success': False, 'message': str(e)})

# ── Remove Rate Limit (POST only) ────────────────────────
@app.route('/api/removelimit/<device_name>/<path:intf>', methods=['POST'])
def api_removelimit(device_name, intf):
    device = get_device_by_name(device_name)
    if not device:
        return jsonify({'success': False, 'message': 'Device not found'})
    try:
        conn_params = get_device_conn_params(device)
        with ConnectHandler(**conn_params) as net:
            net.enable()
            output = net.send_config_set([
                f"interface {intf}",
                "no rate-limit input  50000000 8000 8000 conform-action transmit exceed-action drop",
                "no rate-limit output 50000000 8000 8000 conform-action transmit exceed-action drop"
            ])
        log.info(f"Rate limit removed: {device_name} — {intf}")
        return jsonify({'success': True, 'output': output})
    except Exception as e:
        log.error(f"Remove limit failed: {device_name} — {intf}: {e}")
        return jsonify({'success': False, 'message': str(e)})

# ── SocketIO — push alerts real-time ─────────────────────
def push_anomaly(anomaly):
    socketio.emit('anomaly', anomaly)

def push_device_down(info):
    """แจ้งเตือนบน Dashboard เมื่ออุปกรณ์เชื่อมต่อไม่ได้"""
    socketio.emit('device_down', info)

def run_dashboard():
    log.info("Dashboard starting on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, log_output=False)
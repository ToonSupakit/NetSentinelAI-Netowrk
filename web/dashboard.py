from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO
from functools import wraps
from app.db import (
    get_device_status,
    get_anomaly_history,
    get_analytics,
    authenticate_user,
    create_user,
    get_all_users,
    delete_user,
    update_user_role,
    mark_anomalies_fixed_for_interface,
    engine,
)
from app.runtime import request_collect_now
from app.model_registry import load_metadata
from app.vendor_adapters import remediation_commands, supported_vendors
from web.api_serializers import (
    serialize_analytics,
    serialize_anomaly_rows,
    serialize_status_rows,
    serialize_traffic_rows,
)
from web.remediation_helpers import parse_rate_limit_payload
from app.security import DEFAULT_FLASK_SECRET, device_credential, is_production, runtime_secret
from web.settings_helpers import (
    ENV_SECRET_KEYS,
    env_nonempty as _env_nonempty,
    update_env_file,
    validate_config_payload,
    validate_devices_payload,
    validate_env_payload,
)
from sqlalchemy import text
from netmiko import ConnectHandler
import yaml
import os
import subprocess
import sys
import threading
import time
import logging
import secrets
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

with open("config/devices.yaml", "r", encoding="utf-8") as f:
    devices_config = yaml.safe_load(f)

def _truthy_env(key):
    return os.getenv(key, "").strip().lower() in ("1", "true", "yes", "on")


def _socketio_cors_origins():
    raw = os.getenv("SOCKETIO_CORS_ORIGINS", "").strip()
    if not raw:
        return None
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


app = Flask(__name__)
app.config["SECRET_KEY"] = runtime_secret("FLASK_SECRET", DEFAULT_FLASK_SECRET)
app.config["PERMANENT_SESSION_LIFETIME"] = 3600 * 8  # 8 ชั่วโมง
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _truthy_env("SESSION_COOKIE_SECURE") or is_production()
app.config["SESSION_COOKIE_NAME"] = os.getenv(
    "SESSION_COOKIE_NAME",
    "__Host-netsentinel-session" if app.config["SESSION_COOKIE_SECURE"] else "netsentinel_session",
)
socketio = SocketIO(app, cors_allowed_origins=_socketio_cors_origins())

ENV_PATH = os.getenv("NETSENTINEL_ENV_PATH", ".env")

_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE"})
_ADMIN_ACTION_LIMIT = 30
_ADMIN_ACTION_WINDOW = 60
admin_action_attempts = {}
retrain_lock = threading.Lock()
retrain_job = {
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "returncode": None,
    "log": "",
}

audit = logging.getLogger("audit")
if not any(
    isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "").endswith("audit.log") for h in audit.handlers
):
    os.makedirs("logs", exist_ok=True)
    audit_handler = logging.FileHandler("logs/audit.log", encoding="utf-8")
    audit_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    audit.addHandler(audit_handler)
audit.setLevel(logging.INFO)
audit.propagate = False


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def _inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def audit_log(action, success=True, details=None):
    details = details or {}
    safe = {}
    for k, v in details.items():
        if any(s in str(k).lower() for s in ("pass", "token", "secret", "community")):
            safe[k] = "<redacted>"
        else:
            safe[k] = v
    audit.info(
        "action=%s success=%s user_id=%s username=%s role=%s ip=%s details=%s",
        action,
        bool(success),
        session.get("user_id"),
        session.get("username"),
        session.get("role"),
        request.remote_addr if request else None,
        safe,
    )


@app.before_request
def _require_csrf_token():
    if request.method not in _MUTATING_METHODS:
        return None
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not provided or not secrets.compare_digest(str(expected), str(provided)):
        audit_log("csrf_rejected", success=False, details={"path": request.path, "method": request.method})
        return jsonify({"success": False, "message": "Invalid CSRF token"}), 400
    return None


@socketio.on("connect")
def _socketio_connect():
    if not session.get("logged_in"):
        return False


# ── Rate Limiting ────────────────────────────────────────
login_attempts = {}  # {ip: [timestamp, timestamp, ...]}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 นาที


def is_rate_limited(ip):
    """ตรวจว่า IP นี้ถูกล็อคอยู่ไหม"""
    now = time.time()
    if ip not in login_attempts:
        return False
    # ลบ attempts ที่เก่ากว่า LOCKOUT_SECONDS
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS


def record_attempt(ip):
    """บันทึกการพยายาม login"""
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(time.time())


def clear_attempts(ip):
    """ล้าง attempts เมื่อ login สำเร็จ"""
    login_attempts.pop(ip, None)


def get_remaining_lockout(ip):
    """คืนค่าเวลาที่เหลือก่อนปลดล็อค (วินาที)"""
    if ip not in login_attempts or not login_attempts[ip]:
        return 0
    oldest = min(login_attempts[ip])
    remaining = LOCKOUT_SECONDS - (time.time() - oldest)
    return max(0, int(remaining))


# ── Auth Decorator ───────────────────────────────────────
def admin_action_rate_limited(action):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            now = time.time()
            user_key = session.get("user_id") or request.remote_addr or "unknown"
            key = (str(user_key), action)
            attempts = [t for t in admin_action_attempts.get(key, []) if now - t < _ADMIN_ACTION_WINDOW]
            if len(attempts) >= _ADMIN_ACTION_LIMIT:
                admin_action_attempts[key] = attempts
                audit_log("admin_action_rate_limited", success=False, details={"action": action})
                return jsonify({"success": False, "message": "Too many admin actions. Try again shortly."}), 429
            attempts.append(now)
            admin_action_attempts[key] = attempts
            return f(*args, **kwargs)

        return decorated

    return decorator


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Admin privileges required"}), 403
            return redirect("/")
        return f(*args, **kwargs)

    return decorated


def get_device_by_name(name):
    for d in devices_config["devices"]:
        if d["name"] == name:
            return d
    return None


def get_device_conn_params(device):
    """อ่าน credential จาก device หรือจาก os.environ ล่าสุด (หลังบันทึก .env จาก UI)"""
    return {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": device_credential(device, "username", "DEVICE_USERNAME"),
        "password": device_credential(device, "password", "DEVICE_PASSWORD"),
        "secret": device_credential(device, "secret", "DEVICE_SECRET"),
    }


# ── Auth Routes ──────────────────────────────────────────
@app.route("/login", methods=["GET"])
def login_page():
    if session.get("logged_in"):
        return redirect("/")
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr

    if is_rate_limited(ip):
        remaining = get_remaining_lockout(ip)
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Too many attempts. Try again in {remaining}s",
                    "locked": True,
                    "remaining": remaining,
                }
            ),
            429,
        )

    data = request.json
    if not data:
        return jsonify({"success": False, "message": "No data"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = authenticate_user(username, password)
    if user:
        clear_attempts(ip)
        session["logged_in"] = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session.permanent = True
        log.info(f"Login success from {ip}: {username}")
        audit_log("login", success=True, details={"username": username})
        return jsonify({"success": True})
    else:
        record_attempt(ip)
        attempts_left = MAX_ATTEMPTS - len(login_attempts.get(ip, []))
        log.warning(f"Login failed from {ip}: {username} ({attempts_left} left)")
        audit_log("login", success=False, details={"username": username})
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Invalid credentials ({max(0, attempts_left)} attempts left)",
                    "locked": attempts_left <= 0,
                }
            ),
            401,
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ── Page Routes (Protected) ─────────────────────────────
@app.route("/")
@login_required
def index():
    return render_template("dashboard.html")


@app.route("/traffic")
@login_required
def traffic_page():
    return render_template("traffic.html")


def in_same_30_subnet(ip1, ip2):
    try:
        p1 = list(map(int, ip1.split('.')))
        p2 = list(map(int, ip2.split('.')))
        if len(p1) != 4 or len(p2) != 4:
            return False
        if p1[0:3] != p2[0:3]:
            return False
        return (p1[3] // 4) == (p2[3] // 4)
    except Exception:
        return False


@app.route("/topology")
@login_required
def topology_page():
    return render_template("topology.html")


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html")


@app.route("/api/syslogs", methods=["GET"])
@login_required
def api_get_syslogs():
    device = request.args.get("device", "all")
    severity = request.args.get("severity", "all")
    search = request.args.get("search", "")
    lang = request.args.get("lang", "th")
    
    query = "SELECT device_name, ip_address, facility, severity, mnemonic, message, ai_cause, ai_suggestion, received_at FROM device_syslogs WHERE 1=1"
    params = {}
    
    if device != "all":
        query += " AND device_name = :device"
        params["device"] = device
    if severity != "all":
        query += " AND severity = :severity"
        params["severity"] = severity
    if search:
        query += " AND (message LIKE :search OR mnemonic LIKE :search OR facility LIKE :search)"
        params["search"] = f"%{search}%"
        
    query += " ORDER BY received_at DESC LIMIT 100"
    
    try:
        with engine.connect() as conn:
            rows = conn.execute(text(query), params).fetchall()
            logs = []
            if lang == "en":
                from app.syslog_server import analyze_syslog_ai
            for r in rows:
                ai_cause = r[6]
                ai_suggestion = r[7]
                if lang == "en":
                    ai_cause, ai_suggestion = analyze_syslog_ai(r[2], r[4], r[5], lang="en")
                logs.append({
                    "device_name": r[0],
                    "ip_address": r[1],
                    "facility": r[2],
                    "severity": r[3],
                    "mnemonic": r[4],
                    "message": r[5],
                    "ai_cause": ai_cause,
                    "ai_suggestion": ai_suggestion,
                    "received_at": r[8].strftime("%Y-%m-%d %H:%M:%S") if r[8] else ""
                })
            return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/syslogs/analyze", methods=["POST"])
@login_required
def api_analyze_syslog_ondemand():
    data = request.json
    if not data or not data.get("log_text"):
        return jsonify({"success": False, "message": "Log text required"}), 400
        
    log_text = data["log_text"]
    
    facility = "SYS"
    mnemonic = "GENERIC"
    message = log_text
    
    import re
    cisco_pattern = r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):\s*(.*)"
    cisco_match = re.search(cisco_pattern, log_text)
    if cisco_match:
        facility = cisco_match.group(1)
        mnemonic = cisco_match.group(3)
        message = cisco_match.group(4).strip()
        
    from app.syslog_server import analyze_syslog_ai
    lang = request.args.get("lang", "th")
    ai_cause, ai_suggestion = analyze_syslog_ai(facility, mnemonic, message, lang=lang)
    
    return jsonify({
        "success": True,
        "facility": facility,
        "mnemonic": mnemonic,
        "message": message,
        "ai_cause": ai_cause,
        "ai_suggestion": ai_suggestion
    })


@app.route("/api/syslog/status", methods=["GET"])
@login_required
def api_syslog_status():
    """Return the current syslog server status (running, port, count)."""
    from app.syslog_server import syslog_server_instance
    status = syslog_server_instance.get_status()
    return jsonify({"success": True, **status})


@app.route("/api/syslog/test", methods=["POST"])
@login_required
def api_syslog_test():
    """Send a test syslog message to verify the pipeline works end-to-end."""
    from app.syslog_server import syslog_server_instance
    if not syslog_server_instance.running:
        return jsonify({"success": False, "message": "Syslog server is not running"}), 503
    ok, msg = syslog_server_instance.send_test()
    return jsonify({"success": ok, "message": msg})


@app.route("/api/topology", methods=["GET"])
@login_required
def api_topology():
    try:
        try:
            with open("config/devices.yaml", "r", encoding="utf-8") as f:
                dev_conf = yaml.safe_load(f) or {}
            active_devices = [d["name"] for d in dev_conf.get("devices", []) if "name" in d]
        except Exception:
            active_devices = None
        status_rows = get_device_status(active_devices)
        
        # 1. Map database status rows for robust lookup
        def normalize_intf(name):
            n = str(name).lower().replace(" ", "")
            n = n.replace("fastethernet", "fa")
            n = n.replace("gigabitethernet", "gi")
            n = n.replace("serial", "se")
            return n

        status_map = {}
        for r in status_rows:
            # key: (device_name.lower(), normalized_interface)
            status_map[(r[0].lower(), normalize_intf(r[1]))] = {
                "ip": r[2],
                "status": r[3],
                "txload": r[5],
                "rxload": r[6],
                "label": r[8]
            }

        # 2. Build Nodes (devices)
        devices = []
        for d in devices_config["devices"]:
            # Check if this device is down based on its 'ALL' status
            dev_all = status_map.get((d["name"].lower(), "all"))
            is_down = False
            if dev_all:
                if dev_all["status"] in ("down", "offline", "Cannot Connect"):
                    is_down = True
            else:
                is_down = True # brand new, never collected
                
            if not is_down:
                devices.append({
                    "id": d["name"],
                    "name": d["name"],
                    "role": d.get("role", "core"),
                    "zone": d.get("zone", "Core"),
                    "host": d["host"],
                    "status": "up"
                })
            
        # Ensure Client-1 and Client-2 are dynamically added to the nodes list so they display on the map
        registered_names = [d["id"] for d in devices]
        
        # Determine Client-1 status: it depends on SW-L2-1
        sw1_all = status_map.get(("sw-l2-1", "all"))
        sw1_down = True
        if sw1_all and sw1_all["status"] not in ("down", "offline", "Cannot Connect"):
            sw1_down = False
            
        # Determine Client-2 status: it depends on SW-L2-2
        sw2_all = status_map.get(("sw-l2-2", "all"))
        sw2_down = True
        if sw2_all and sw2_all["status"] not in ("down", "offline", "Cannot Connect"):
            sw2_down = False

        if "Client-1" not in registered_names and not sw1_down:
            devices.append({
                "id": "Client-1",
                "name": "Client-1",
                "role": "client",
                "zone": "A",
                "host": "10.10.3.10",
                "status": "up"
            })
        if "Client-2" not in registered_names and not sw2_down:
            devices.append({
                "id": "Client-2",
                "name": "Client-2",
                "role": "client",
                "zone": "Core",
                "host": "10.10.2.10",
                "status": "up"
            })

        # Define the exact backbone connections matching the GNS3 topology
        backbone_links = [
            ("R1", "FastEthernet0/1", "R2", "FastEthernet0/0"),
            ("R2", "FastEthernet0/1", "ESW1", "FastEthernet0/0"),
            ("R2", "FastEthernet1/0", "ESW2", "FastEthernet0/0"),
            ("ESW1", "FastEthernet0/1", "SW-L2-1", "GigabitEthernet0/0"),
            ("SW-L2-1", "GigabitEthernet0/1", "Client-1", "eth0"),
            ("ESW2", "FastEthernet0/1", "SW-L2-2", "GigabitEthernet0/0"),
            ("SW-L2-2", "GigabitEthernet0/1", "Client-2", "eth0"),
        ]

        edges = []
        for dev1, intf1, dev2, intf2 in backbone_links:
            # Check if both nodes exist in the devices list
            valid_names = [d["id"] for d in devices]
            if dev1 not in valid_names or dev2 not in valid_names:
                continue

            # Check if either device is down
            dev1_is_polled = any(d["name"] == dev1 for d in devices_config["devices"])
            dev2_is_polled = any(d["name"] == dev2 for d in devices_config["devices"])

            dev1_is_down = False
            if dev1_is_polled:
                dev1_all = status_map.get((dev1.lower(), "all"))
                if dev1_all:
                    if dev1_all["status"] in ("down", "offline"):
                        dev1_is_down = True
                else:
                    dev1_is_down = True
            else:
                if dev1 == "Client-1" and sw1_down:
                    dev1_is_down = True
                elif dev1 == "Client-2" and sw2_down:
                    dev1_is_down = True

            dev2_is_down = False
            if dev2_is_polled:
                dev2_all = status_map.get((dev2.lower(), "all"))
                if dev2_all:
                    if dev2_all["status"] in ("down", "offline"):
                        dev2_is_down = True
                else:
                    dev2_is_down = True
            else:
                if dev2 == "Client-1" and sw1_down:
                    dev2_is_down = True
                elif dev2 == "Client-2" and sw2_down:
                    dev2_is_down = True

            state1 = status_map.get((dev1.lower(), normalize_intf(intf1)), {
                "ip": "unassigned", "status": "up", "txload": 1, "rxload": 1, "label": "normal"
            })
            state2 = status_map.get((dev2.lower(), normalize_intf(intf2)), {
                "ip": "unassigned", "status": "up", "txload": 1, "rxload": 1, "label": "normal"
            })

            # Override status to down if the parent device is down
            status1 = "down" if dev1_is_down else state1["status"]
            status2 = "down" if dev2_is_down else state2["status"]

            status = "up"
            if status1 in ("down", "admin_down") or status2 in ("down", "admin_down"):
                status = "down"

            label = "normal"
            if state1["label"] == "anomaly" or state2["label"] == "anomaly":
                label = "anomaly"

            edge_id = f"{dev1}::{intf1}-{dev2}::{intf2}"
            edges.append({
                "id": edge_id,
                "source": dev1,
                "target": dev2,
                "source_interface": intf1,
                "target_interface": intf2,
                "source_ip": state1["ip"],
                "target_ip": state2["ip"],
                "source_status": status1,
                "target_status": status2,
                "source_txload": state1["txload"],
                "source_rxload": state1["rxload"],
                "target_txload": state2["txload"],
                "target_rxload": state2["rxload"],
                "status": status,
                "label": label
            })
                    
        return jsonify({
            "success": True,
            "nodes": devices,
            "edges": edges
        })
    except Exception as e:
        log.error("Failed to generate topology data: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


# ── Config Backups & Diff Engine ──────────────────────────
backup_status = {
    "status": "idle",
    "progress": 0,
    "current_device": "",
    "log": [],
    "last_run": None
}

def run_backup_worker():
    global backup_status
    backup_status["status"] = "running"
    backup_status["progress"] = 0
    backup_status["current_device"] = ""
    backup_status["log"] = ["Starting backup session..."]
    
    try:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join("backups", timestamp)
        os.makedirs(backup_dir, exist_ok=True)
        
        devices = devices_config.get("devices", [])
        if not devices:
            backup_status["status"] = "failed"
            backup_status["log"].append("No devices configured in devices.yaml!")
            return
            
        default_creds = {"name": "backup-defaults", "host": "backup-defaults"}
        username = device_credential(default_creds, "username", "DEVICE_USERNAME")
        password = device_credential(default_creds, "password", "DEVICE_PASSWORD")
        secret = device_credential(default_creds, "secret", "DEVICE_SECRET")
        
        total = len(devices)
        success_count = 0
        
        for idx, dev in enumerate(devices):
            name = dev.get("name", "Unknown")
            host = dev.get("host")
            device_type = dev.get("device_type", "cisco_ios_telnet")
            
            backup_status["current_device"] = name
            backup_status["log"].append(f"Connecting to {name} ({host})...")
            backup_status["progress"] = int((idx / total) * 100)
            
            try:
                net_connect = ConnectHandler(
                    device_type=device_type,
                    host=host,
                    username=username,
                    password=password,
                    secret=secret,
                    timeout=10,
                )
                net_connect.enable()
                
                backup_status["log"].append(f"  -> Fetching running-config from {name}...")
                run_conf = net_connect.send_command("show run")
                
                filename = f"{name}_run.txt"
                filepath = os.path.join(backup_dir, filename)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(run_conf)
                
                backup_status["log"].append(f"  -> Fetching routing table from {name}...")
                route_conf = net_connect.send_command("show ip route")
                route_filename = f"{name}_route.txt"
                route_filepath = os.path.join(backup_dir, route_filename)
                with open(route_filepath, "w", encoding="utf-8") as f:
                    f.write(route_conf)
                    
                net_connect.disconnect()
                
                backup_status["log"].append(f"✅ {name} configuration backed up successfully.")
                success_count += 1
            except Exception as e:
                backup_status["log"].append(f"❌ Failed to backup {name}: {str(e)}")
                
        backup_status["progress"] = 100
        backup_status["current_device"] = ""
        backup_status["last_run"] = timestamp
        
        if success_count == total:
            backup_status["status"] = "success"
            backup_status["log"].append(f"🎉 Backup completed! Successfully backed up {success_count}/{total} devices.")
        elif success_count > 0:
            backup_status["status"] = "success"
            backup_status["log"].append(f"⚠️ Backup completed with warnings. Backed up {success_count}/{total} devices.")
        else:
            backup_status["status"] = "failed"
            backup_status["log"].append("❌ Backup session failed. Could not connect to any devices.")
            
    except Exception as ex:
        backup_status["status"] = "failed"
        backup_status["log"].append(f"Fatal error during backup session: {str(ex)}")

@app.route("/backups")
@login_required
def backups_page():
    return render_template("backups.html")

@app.route("/api/backups/run", methods=["POST"])
@login_required
def api_run_backup():
    global backup_status
    if backup_status["status"] == "running":
        return jsonify({"success": False, "message": "A backup session is already in progress."})
        
    t = threading.Thread(target=run_backup_worker, daemon=True)
    t.start()
    return jsonify({"success": True, "message": "Backup session started in background."})

@app.route("/api/backups/status", methods=["GET"])
@login_required
def api_backup_status():
    global backup_status
    return jsonify({"success": True, "data": backup_status})

@app.route("/api/backups/sessions", methods=["GET"])
@login_required
def api_backup_sessions():
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            return jsonify({"success": True, "sessions": []})
            
        sessions = []
        for name in os.listdir(backup_dir):
            path = os.path.join(backup_dir, name)
            if os.path.isdir(path):
                files = os.listdir(path)
                configs = [f for f in files if f.endswith("_run.txt")]
                
                total_size = sum(os.path.getsize(os.path.join(path, f)) for f in files)
                
                sessions.append({
                    "id": name,
                    "timestamp": name,
                    "device_count": len(configs),
                    "size_bytes": total_size,
                    "devices": [f.replace("_run.txt", "") for f in configs]
                })
                
        sessions.sort(key=lambda s: s["id"], reverse=True)
        return jsonify({"success": True, "sessions": sessions})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/backups/session/<session_id>", methods=["GET"])
@login_required
def api_backup_session_files(session_id):
    try:
        session_id = os.path.basename(session_id)
        path = os.path.join("backups", session_id)
        if not os.path.exists(path) or not os.path.isdir(path):
            return jsonify({"success": False, "message": "Session not found."}), 404
            
        files = os.listdir(path)
        configs = [{"name": f.replace("_run.txt", ""), "type": "config", "filename": f} for f in files if f.endswith("_run.txt")]
        routes = [{"name": f.replace("_route.txt", ""), "type": "route", "filename": f} for f in files if f.endswith("_route.txt")]
        
        return jsonify({
            "success": True,
            "session_id": session_id,
            "configs": configs,
            "routes": routes
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/backups/session/<session_id>/file/<filename>", methods=["GET"])
@login_required
def api_backup_file_content(session_id, filename):
    try:
        session_id = os.path.basename(session_id)
        filename = os.path.basename(filename)
        path = os.path.join("backups", session_id, filename)
        if not os.path.exists(path):
            return jsonify({"success": False, "message": "File not found."}), 404
            
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        return jsonify({
            "success": True,
            "session_id": session_id,
            "filename": filename,
            "content": content
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/backups/diff", methods=["GET"])
@login_required
def api_backup_diff():
    try:
        session_a = request.args.get("session_a")
        session_b = request.args.get("session_b")
        filename = request.args.get("filename")
        
        if not session_a or not session_b or not filename:
            return jsonify({"success": False, "message": "Missing session_a, session_b, or filename."}), 400
            
        session_a = os.path.basename(session_a)
        session_b = os.path.basename(session_b)
        filename = os.path.basename(filename)
        
        path_a = os.path.join("backups", session_a, filename)
        path_b = os.path.join("backups", session_b, filename)
        
        text_a = ""
        text_b = ""
        
        if os.path.exists(path_a):
            with open(path_a, "r", encoding="utf-8", errors="ignore") as f:
                text_a = f.read()
        if os.path.exists(path_b):
            with open(path_b, "r", encoding="utf-8", errors="ignore") as f:
                text_b = f.read()
                
        import difflib
        a_lines = text_a.splitlines()
        b_lines = text_b.splitlines()
        
        diff = difflib.ndiff(a_lines, b_lines)
        
        diff_lines = []
        line_a_num = 0
        line_b_num = 0
        
        for line in diff:
            if line.startswith("- "):
                line_a_num += 1
                diff_lines.append({
                    "type": "delete",
                    "line_a": line_a_num,
                    "line_b": "",
                    "text": line[2:]
                })
            elif line.startswith("+ "):
                line_b_num += 1
                diff_lines.append({
                    "type": "add",
                    "line_a": "",
                    "line_b": line_b_num,
                    "text": line[2:]
                })
            elif line.startswith("  "):
                line_a_num += 1
                line_b_num += 1
                diff_lines.append({
                    "type": "normal",
                    "line_a": line_a_num,
                    "line_b": line_b_num,
                    "text": line[2:]
                })
            elif line.startswith("? "):
                continue
                
        return jsonify({
            "success": True,
            "filename": filename,
            "session_a": session_a,
            "session_b": session_b,
            "diff": diff_lines
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/settings")
@admin_required
def settings_page():
    return render_template("settings.html")


# ── API Routes (Protected) ──────────────────────────────
@app.route("/api/health")
def api_health():
    try:
        from app.db import engine

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "db": str(e)}), 500


@app.route("/api/status")
@login_required
def api_status():
    try:
        try:
            with open("config/devices.yaml", "r", encoding="utf-8") as f:
                dev_conf = yaml.safe_load(f) or {}
            active_devices = [d["name"] for d in dev_conf.get("devices", []) if "name" in d]
        except Exception:
            active_devices = None
            dev_conf = {}

        raw_rows = get_device_status(active_devices)

        # 1. Map database status rows for ALL interface to check if device is down
        device_down_map = {}
        for r in raw_rows:
            dev_name = r[0]
            intf_name = r[1]
            status = r[3]
            if intf_name == "ALL":
                if status in ("down", "offline"):
                    device_down_map[dev_name.lower()] = True
                else:
                    device_down_map[dev_name.lower()] = False

        # Any active device that has no logs in the DB is considered down
        for d in dev_conf.get("devices", []):
            dname = d["name"].lower()
            if dname not in device_down_map:
                device_down_map[dname] = True

        backbone_interfaces = {
            "r1": [("FastEthernet0/0", "192.168.189.10"), ("FastEthernet0/1", "10.10.1.1")],
            "r2": [("FastEthernet0/0", "10.10.1.2"), ("FastEthernet0/1", "10.10.3.1"), ("FastEthernet1/0", "10.10.2.1")],
            "esw1": [("FastEthernet0/0", "10.10.3.2"), ("FastEthernet0/1", "unassigned")],
            "esw2": [("FastEthernet0/0", "10.10.2.2"), ("FastEthernet0/1", "unassigned")],
            "sw-l2-1": [("GigabitEthernet0/0", "10.10.100.4"), ("GigabitEthernet0/1", "unassigned")],
            "sw-l2-2": [("GigabitEthernet0/0", "10.10.3.100"), ("GigabitEthernet0/1", "unassigned")],
        }

        # 2. Build overridden rows list
        processed_rows = []
        import datetime
        now_str = str(datetime.datetime.now())

        for d in dev_conf.get("devices", []):
            dname = d["name"]
            dname_lower = dname.lower()
            is_down = device_down_map.get(dname_lower, True)

            # Get all DB rows for this device that are NOT 'ALL'
            dev_rows = [r for r in raw_rows if r[0].lower() == dname_lower and r[1] != "ALL"]

            if is_down:
                if dev_rows:
                    for r in dev_rows:
                        processed_rows.append({
                            "device": r[0],
                            "interface": r[1],
                            "ip": r[2],
                            "status": "Cannot Connect",
                            "protocol": "down",
                            "network_load": 0,
                            "rxload": 0,
                            "reliability": 0,
                            "label": "anomaly",
                            "collected_at": str(r[9])
                        })
                else:
                    default_intfs = backbone_interfaces.get(dname_lower, [("Management", d["host"])])
                    for intf, ip in default_intfs:
                        processed_rows.append({
                            "device": dname,
                            "interface": intf,
                            "ip": ip,
                            "status": "Cannot Connect",
                            "protocol": "down",
                            "network_load": 0,
                            "rxload": 0,
                            "reliability": 0,
                            "label": "anomaly",
                            "collected_at": now_str
                        })
            else:
                for r in dev_rows:
                    processed_rows.append({
                        "device": r[0],
                        "interface": r[1],
                        "ip": r[2],
                        "status": r[3],
                        "protocol": r[4],
                        "network_load": r[5],
                        "rxload": r[6],
                        "reliability": r[7],
                        "label": r[8],
                        "collected_at": str(r[9])
                    })

        return jsonify(processed_rows)
    except Exception as e:
        log.error("Failed to load status data: %s", e)
        return jsonify({"success": False, "message": "Status data unavailable"}), 500


@app.route("/api/anomalies")
@login_required
def api_anomalies():
    try:
        return jsonify(serialize_anomaly_rows(get_anomaly_history(limit=50)))
    except Exception as e:
        log.error("Failed to load anomaly data: %s", e)
        return jsonify({"success": False, "message": "Anomaly data unavailable"}), 500


@app.route("/api/analytics")
@login_required
def api_analytics():
    try:
        return jsonify(serialize_analytics(get_analytics()))
    except Exception as e:
        log.error("Failed to load analytics data: %s", e)
        return jsonify({"success": False, "message": "Analytics data unavailable"}), 500


@app.route("/api/traffic")
@login_required
def api_traffic():
    try:
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
        return jsonify(serialize_traffic_rows(rows))
    except Exception as e:
        log.error("Failed to load traffic data: %s", e)
        return jsonify({"success": False, "message": "Traffic data unavailable"}), 500


def _model_path():
    return config.get("model", {}).get("path", "models/anomaly_model_v2.pkl")


def _trim_log(text, limit=12000):
    text = text or ""
    return text[-limit:] if len(text) > limit else text


def run_retrain_task():
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    with retrain_lock:
        retrain_job.update(
            {
                "status": "running",
                "started_at": started,
                "finished_at": None,
                "returncode": None,
                "log": f"[{started}] Retrain started\n",
            }
        )
    try:
        result = subprocess.run(
            [sys.executable, "train_model.py"],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        output = (result.stdout or "") + (("\nSTDERR:\n" + result.stderr) if result.stderr else "")
        status = "success" if result.returncode == 0 else "failed"
        if result.returncode == 0:
            try:
                from app.predictor import reload_model

                reload_model()
            except Exception as e:
                output += f"\nModel reload failed: {e}"
                status = "failed"
        finished = time.strftime("%Y-%m-%d %H:%M:%S")
        with retrain_lock:
            retrain_job.update(
                {
                    "status": status,
                    "finished_at": finished,
                    "returncode": result.returncode,
                    "log": _trim_log(retrain_job.get("log", "") + output + f"\n[{finished}] Retrain {status}\n"),
                }
            )
        socketio.emit("model_retrain", {"status": status})
    except subprocess.TimeoutExpired:
        finished = time.strftime("%Y-%m-%d %H:%M:%S")
        with retrain_lock:
            retrain_job.update(
                {
                    "status": "failed",
                    "finished_at": finished,
                    "returncode": None,
                    "log": _trim_log(retrain_job.get("log", "") + f"[{finished}] Retrain timed out after 3600s\n"),
                }
            )
        socketio.emit("model_retrain", {"status": "failed"})
    except Exception as e:
        finished = time.strftime("%Y-%m-%d %H:%M:%S")
        with retrain_lock:
            retrain_job.update(
                {
                    "status": "failed",
                    "finished_at": finished,
                    "returncode": None,
                    "log": _trim_log(retrain_job.get("log", "") + f"[{finished}] Retrain error: {e}\n"),
                }
            )
        socketio.emit("model_retrain", {"status": "failed"})


@app.route("/api/model/status")
@login_required
def api_model_status():
    try:
        metadata = load_metadata(_model_path())
        with retrain_lock:
            job = dict(retrain_job)
        return jsonify(
            {
                "success": True,
                "metadata": metadata,
                "retrain": job,
                "supported_vendors": supported_vendors(),
            }
        )
    except Exception as e:
        log.error("Failed to load model status: %s", e)
        return jsonify({"success": False, "message": "Model status unavailable"}), 500


@app.route("/api/model/retrain", methods=["POST"])
@admin_required
@admin_action_rate_limited("model_retrain")
def api_model_retrain():
    with retrain_lock:
        if retrain_job.get("status") == "running":
            return jsonify({"success": False, "message": "Retrain already running"}), 409
        retrain_job.update({"status": "queued", "log": "Retrain queued\n"})
    socketio.start_background_task(run_retrain_task)
    audit_log("model_retrain_queued")
    return jsonify({"success": True, "message": "Retrain queued", "queued": True})


# ── Fix / Rate Limit (Protected) ────────────────────────
active_limits = {}  # {device_name::intf: limit_mbps}


def execute_remediation_task(device_name, intf, action, limit_mbps=None):
    """Background task: connect to device and execute remediation commands."""
    device = get_device_by_name(device_name)
    if not device:
        socketio.emit("remediation_result", {"success": False, "message": f"Device {device_name} not found"})
        return

    # For removelimit, retrieve stored limit value
    key = f"{device_name}::{intf}"
    if action == "removelimit" and not limit_mbps:
        limit_mbps = active_limits.get(key)
        if not limit_mbps and "cisco" in device["device_type"]:
            socketio.emit(
                "remediation_result", {"success": False, "message": f"No active limit found for {device_name} - {intf}"}
            )
            return

    cmds = remediation_commands(device["device_type"], intf, action, limit_mbps)
    if not cmds:
        socketio.emit(
            "remediation_result",
            {"success": False, "message": f'Action "{action}" not supported for device type: {device["device_type"]}'},
        )
        return

    try:
        conn_params = get_device_conn_params(device)
        with ConnectHandler(**conn_params) as net:
            if "cisco" in device["device_type"] or "arista" in device["device_type"]:
                net.enable()
            output = net.send_config_set(cmds)

        # Track / untrack active limits
        if action == "limit":
            active_limits[key] = limit_mbps
        elif action == "removelimit":
            active_limits.pop(key, None)

        if action == "fix":
            try:
                mark_anomalies_fixed_for_interface(device_name, intf)
            except Exception as ex:
                log.warning("mark_anomalies_fixed_for_interface: %s", ex)

            # Immediately insert a normal up log into the DB so UI updates instantly
            try:
                from datetime import datetime
                with engine.connect() as conn:
                    latest_row = conn.execute(
                        text("""
                            SELECT ip_address, reliability, network_load, rxload, input_errors, link_type, zone, location 
                            FROM interface_logs 
                            WHERE device_name = :dev AND interface_name = :intf 
                            ORDER BY collected_at DESC LIMIT 1
                        """),
                        {"dev": device_name, "intf": intf}
                    ).fetchone()

                    if latest_row:
                        ip_address, reliability, network_load, rxload, input_errors, link_type, zone, location = latest_row
                        conn.execute(
                            text("""
                                INSERT INTO interface_logs 
                                (device_name, interface_name, ip_address, status, protocol, reliability, network_load, rxload, input_errors, link_type, zone, location, label, collected_at, created_at)
                                VALUES (:dev, :intf, :ip, 'up', 'up', :rel, :load, :rx, :err, :ltype, :zone, :loc, 'normal', :now, :now)
                            """),
                            {
                                "dev": device_name,
                                "intf": intf,
                                "ip": ip_address,
                                "rel": reliability,
                                "load": network_load,
                                "rx": rxload,
                                "err": input_errors,
                                "ltype": link_type,
                                "zone": zone,
                                "loc": location,
                                "now": datetime.now()
                            }
                        )
                        conn.commit()
            except Exception as db_ex:
                log.warning("Failed to insert immediate up state: %s", db_ex)

        label = {"fix": "Fix", "limit": f"Limit ({limit_mbps} Mbps)", "removelimit": "Remove Limit"}
        log.info(f"Remediation ({action}): {device_name} — {intf} successful")

        # Emit successful result immediately to unblock UI loading spinner
        socketio.emit(
            "remediation_result",
            {
                "success": True,
                "message": f"{label.get(action, action)} completed on {device_name} - {intf}",
                "device": device_name,
                "intf": intf,
                "action": action,
            },
        )

        # Trigger background re-collection after router stabilizes without blocking the UI
        def run_delayed_collect():
            import time as _time
            _time.sleep(2)
            request_collect_now()
        socketio.start_background_task(run_delayed_collect)
    except Exception as e:
        log.error(f"Remediation ({action}) failed: {device_name} — {intf}: {e}")
        socketio.emit(
            "remediation_result",
            {
                "success": False,
                "message": f"{action.capitalize()} failed on {device_name} - {intf}: {str(e)}",
                "device": device_name,
                "intf": intf,
                "action": action,
            },
        )


def auto_rollback_task(device_name, intf, limit_mbps, delay_minutes):
    """Background task: wait then auto-remove rate limit."""
    import time as _time

    _time.sleep(delay_minutes * 60)
    key = f"{device_name}::{intf}"
    if active_limits.get(key) == limit_mbps:
        log.info(f"Auto-rollback triggered: {device_name} — {intf} after {delay_minutes} min")
        execute_remediation_task(device_name, intf, "removelimit", limit_mbps)
    else:
        log.info(f"Auto-rollback skipped (limit changed): {device_name} — {intf}")


@app.route("/api/fix/<device_name>/<path:intf>", methods=["POST"])
@login_required
@admin_action_rate_limited("fix")
def api_fix(device_name, intf):
    socketio.start_background_task(execute_remediation_task, device_name, intf, "fix")
    audit_log("fix_queued", details={"device": device_name, "interface": intf})
    return jsonify({"success": True, "message": "Fix queued (port bounce)...", "queued": True})


@app.route("/api/ratelimit/<device_name>/<path:intf>", methods=["POST"])
@login_required
@admin_action_rate_limited("ratelimit")
def api_ratelimit(device_name, intf):
    data = request.json or {}
    ok, limit_mbps, rollback_min, message, error_code = parse_rate_limit_payload(data)
    if not ok:
        audit_log(
            "ratelimit_queued",
            success=False,
            details={"device": device_name, "interface": intf, "error": error_code},
        )
        return jsonify({"success": False, "message": message}), 400

    socketio.start_background_task(execute_remediation_task, device_name, intf, "limit", limit_mbps)

    # Schedule auto-rollback if requested
    if rollback_min > 0:
        socketio.start_background_task(auto_rollback_task, device_name, intf, limit_mbps, rollback_min)

    msg = f"Limit ({limit_mbps} Mbps) queued..."
    if rollback_min > 0:
        msg += f" Auto-remove in {rollback_min} min."
    audit_log(
        "ratelimit_queued",
        details={"device": device_name, "interface": intf, "limit_mbps": limit_mbps, "rollback_min": rollback_min},
    )
    return jsonify({"success": True, "message": msg, "queued": True})


@app.route("/api/removelimit/<device_name>/<path:intf>", methods=["POST"])
@login_required
@admin_action_rate_limited("removelimit")
def api_removelimit(device_name, intf):
    socketio.start_background_task(execute_remediation_task, device_name, intf, "removelimit")
    audit_log("removelimit_queued", details={"device": device_name, "interface": intf})
    return jsonify({"success": True, "message": "Remove limit queued...", "queued": True})


# ── Settings API (Protected) ────────────────────────────
@app.route("/api/settings/config", methods=["GET"])
@admin_required
def api_get_config():
    try:
        with open("config/config.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return jsonify({"success": True, "data": data})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/settings/config", methods=["POST"])
@admin_required
@admin_action_rate_limited("settings_config")
def api_save_config():
    try:
        new_config = request.json
        if not new_config:
            return jsonify({"success": False, "message": "No data provided"}), 400
        ok, err = validate_config_payload(new_config)
        if not ok:
            audit_log("settings_config_update", success=False, details={"error": err})
            return jsonify({"success": False, "message": err}), 400
        with open("config/config.yaml", "w", encoding="utf-8") as f:
            yaml.dump(new_config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        global config
        config = new_config
        log.info("Config updated via web UI")
        audit_log("settings_config_update", details={"sections": list(new_config.keys())})
        return jsonify({"success": True, "message": "Configuration saved"})
    except Exception as e:
        log.error("Failed to save config: %s", e)
        audit_log("settings_config_update", success=False, details={"error": str(e)})
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/settings/devices", methods=["GET"])
@admin_required
def api_get_devices():
    try:
        with open("config/devices.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return jsonify({"success": True, "data": data})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/settings/devices", methods=["POST"])
@admin_required
@admin_action_rate_limited("settings_devices")
def api_save_devices():
    try:
        new_devices = request.json
        ok, err = validate_devices_payload(new_devices)
        if not ok:
            audit_log("settings_devices_update", success=False, details={"error": err})
            return jsonify({"success": False, "message": err}), 400
        with open("config/devices.yaml", "w", encoding="utf-8") as f:
            yaml.dump(new_devices, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        global devices_config
        devices_config = new_devices
        log.info("Devices config updated via web UI")
        audit_log("settings_devices_update", details={"device_count": len(new_devices.get("devices", []))})
        return jsonify({"success": True, "message": "Devices configuration saved"})
    except Exception as e:
        log.error("Failed to save devices config: %s", e)
        audit_log("settings_devices_update", success=False, details={"error": str(e)})
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/settings/env", methods=["GET"])
@admin_required
def api_get_env():
    """ไม่ส่งค่า secret จริง — แจ้งแค่ว่ามีการตั้งค่าหรือไม่"""
    return jsonify(
        {
            "success": True,
            "data": {
                "DEVICE_USERNAME": os.getenv("DEVICE_USERNAME", ""),
                "SNMP_V3_USER": os.getenv("SNMP_V3_USER", ""),
                "APP_ENV": os.getenv("APP_ENV", ""),
                "SESSION_COOKIE_SECURE": os.getenv("SESSION_COOKIE_SECURE", ""),
                "DASHBOARD_HOST": os.getenv("DASHBOARD_HOST", ""),
                "DASHBOARD_PORT": os.getenv("DASHBOARD_PORT", ""),
                "SOCKETIO_CORS_ORIGINS": os.getenv("SOCKETIO_CORS_ORIGINS", ""),
                "DEVICE_PASSWORD_CONFIGURED": _env_nonempty("DEVICE_PASSWORD"),
                "DEVICE_SECRET_CONFIGURED": _env_nonempty("DEVICE_SECRET"),
                "SNMP_COMMUNITY_CONFIGURED": _env_nonempty("SNMP_COMMUNITY"),
                "SNMP_V3_AUTH_CONFIGURED": _env_nonempty("SNMP_V3_AUTH"),
                "SNMP_V3_PRIV_CONFIGURED": _env_nonempty("SNMP_V3_PRIV"),
                "FLASK_SECRET_CONFIGURED": _env_nonempty("FLASK_SECRET"),
            },
        }
    )


@app.route("/api/settings/env", methods=["POST"])
@admin_required
@admin_action_rate_limited("settings_env")
def api_save_env():
    data = request.json or {}
    try:
        ok, err = validate_env_payload(data)
        if not ok:
            audit_log("settings_env_update", success=False, details={"error": err})
            return jsonify({"success": False, "message": err}), 400
        updates = {}
        for k, v in data.items():
            if v is None:
                continue
            s = str(v).strip()
            if k in ENV_SECRET_KEYS and not s:
                continue
            updates[k] = s
            os.environ[k] = s

        update_env_file(ENV_PATH, updates)
        audit_log("settings_env_update", details={"keys": sorted(updates.keys())})
        return jsonify({"success": True})
    except Exception as e:
        audit_log("settings_env_update", success=False, details={"error": str(e)})
        return jsonify({"success": False, "message": str(e)})


# ── User Management API ──────────────────────────────────
@app.route("/api/users", methods=["GET"])
@admin_required
def api_get_users():
    return jsonify({"success": True, "users": get_all_users()})


@app.route("/api/users", methods=["POST"])
@admin_required
@admin_action_rate_limited("users_create")
def api_create_user():
    data = request.json
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"success": False, "message": "Username and password required"}), 400
    if len(data["username"]) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 characters"}), 400
    if len(data["password"]) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
    role = data.get("role", "user")
    if role not in ("admin", "user"):
        return jsonify({"success": False, "message": "Invalid role"}), 400
    if create_user(data["username"], data["password"], role):
        audit_log("user_create", details={"created_username": data["username"], "role": role})
        return jsonify({"success": True, "message": f"User '{data['username']}' created"})
    audit_log("user_create", success=False, details={"created_username": data["username"], "role": role})
    return jsonify({"success": False, "message": "Username already exists"}), 400


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
@admin_action_rate_limited("users_delete")
def api_delete_user(user_id):
    ok, err = delete_user(user_id, actor_id=session.get("user_id"))
    if ok:
        audit_log("user_delete", details={"target_user_id": user_id})
        return jsonify({"success": True})
    audit_log("user_delete", success=False, details={"target_user_id": user_id, "error": err})
    return jsonify({"success": False, "message": err or "Delete failed"}), 400


@app.route("/api/users/<int:user_id>/role", methods=["PUT"])
@admin_required
@admin_action_rate_limited("users_role")
def api_update_user_role(user_id):
    data = request.json
    role = data.get("role")
    if role not in ["admin", "user"]:
        return jsonify({"success": False, "message": "Invalid role"}), 400
    ok, err = update_user_role(user_id, role)
    if ok:
        audit_log("user_role_update", details={"target_user_id": user_id, "role": role})
        return jsonify({"success": True})
    audit_log("user_role_update", success=False, details={"target_user_id": user_id, "role": role, "error": err})
    return jsonify({"success": False, "message": err or "Update role failed"}), 400


# ── SocketIO ─────────────────────────────────────────────

def push_anomaly(anomaly):
    socketio.emit("anomaly", anomaly)


def push_device_down(info):
    socketio.emit("device_down", info)


def run_dashboard():
    host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.getenv("DASHBOARD_PORT", "5000"))
    log.info("Dashboard starting on http://%s:%s", host, port)
    socketio.run(
        app,
        host=host,
        port=port,
        debug=False,
        use_reloader=False,
        log_output=False,
        allow_unsafe_werkzeug=not is_production(),
    )

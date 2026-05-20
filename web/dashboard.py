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

# Dashboard credentials จาก .env (ใช้เป็น default ตอน seed เท่านั้น)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "netsentinel-secret-key-change-me")
app.config["PERMANENT_SESSION_LIFETIME"] = 3600 * 8  # 8 ชั่วโมง
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "").lower() in (
    "1",
    "true",
    "yes",
    "on",
) or os.getenv("APP_ENV", "").lower() in ("prod", "production")
socketio = SocketIO(app, cors_allowed_origins="*")

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
    audit_handler = logging.FileHandler("audit.log", encoding="utf-8")
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
        "username": device.get("username") or os.getenv("DEVICE_USERNAME", "admin"),
        "password": device.get("password") or os.getenv("DEVICE_PASSWORD", "admin"),
        "secret": device.get("secret") or os.getenv("DEVICE_SECRET", "admin"),
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
        return jsonify(serialize_status_rows(get_device_status()))
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

        label = {"fix": "Fix", "limit": f"Limit ({limit_mbps} Mbps)", "removelimit": "Remove Limit"}
        log.info(f"Remediation ({action}): {device_name} — {intf} successful")

        # Trigger immediate re-collection after router stabilizes
        import time as _time
        _time.sleep(2)
        request_collect_now()
        _time.sleep(1.5)  # Wait briefly for collector thread to run and update DB

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
@admin_required
@admin_action_rate_limited("fix")
def api_fix(device_name, intf):
    socketio.start_background_task(execute_remediation_task, device_name, intf, "fix")
    audit_log("fix_queued", details={"device": device_name, "interface": intf})
    return jsonify({"success": True, "message": "Fix queued (port bounce)...", "queued": True})


@app.route("/api/ratelimit/<device_name>/<path:intf>", methods=["POST"])
@admin_required
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
@admin_required
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
                "DISCORD_CHANNEL_ID": os.getenv("DISCORD_CHANNEL_ID", ""),
                "DEVICE_USERNAME": os.getenv("DEVICE_USERNAME", ""),
                "DISCORD_TOKEN_CONFIGURED": _env_nonempty("DISCORD_TOKEN"),
                "DEVICE_PASSWORD_CONFIGURED": _env_nonempty("DEVICE_PASSWORD"),
                "DEVICE_SECRET_CONFIGURED": _env_nonempty("DEVICE_SECRET"),
                "SNMP_COMMUNITY_CONFIGURED": _env_nonempty("SNMP_COMMUNITY"),
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
    log.info("Dashboard starting on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False, log_output=False)

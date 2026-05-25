import asyncio
import logging
import signal
import subprocess
import sys
import threading
import time
import yaml
from dotenv import load_dotenv

from app.db import init_db, cleanup_old_data
from app.collector import collect_all
from app.predictor import predict_all, reload_model
from app.bot import run_bot, anomaly_queue, client, send_timeout_alert
from app.runtime import shutdown_event, request_shutdown, collect_now_event
from web.dashboard import run_dashboard, push_anomaly, push_device_down
from app.syslog_server import syslog_server_instance

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(module)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler("netsentinel.log", encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

INTERVAL = config.get("collector", {}).get("interval", 10)
RETENTION_DAYS = config.get("data_retention", {}).get("days", 30)
RETRAIN_INTERVAL_HOURS = config.get("model", {}).get("retrain_interval_hours", 24)


def on_timeout(info):
    try:
        if client.is_ready():
            asyncio.run_coroutine_threadsafe(send_timeout_alert(info), client.loop)
    except Exception as e:
        log.error("Failed to send timeout alert to Discord: %s", e)
    push_device_down(info)


def _stop_discord_gracefully():
    """ขอปิด Discord client จากเธรดอื่น (ถ้า event loop ยังรันอยู่)"""
    try:
        loop = getattr(client, "loop", None)
        if loop is not None and loop.is_running() and not client.is_closed():
            fut = asyncio.run_coroutine_threadsafe(client.close(), loop)
            fut.result(timeout=8)
    except Exception as e:
        log.debug("Discord graceful close: %s", e)


def auto_retrain_loop():
    """รัน train_model.py ตามช่วงเวลาใน config (ค่าเริ่มต้น 24 ชม.)"""
    log.info(
        "Auto-retrain enabled: every %s hour(s)",
        RETRAIN_INTERVAL_HOURS,
    )
    total_sec = max(1, int(RETRAIN_INTERVAL_HOURS * 3600))
    while not shutdown_event.is_set():
        # หลับเป็นช่วงสั้นๆ เพื่อให้ตรวจจับ shutdown ได้
        elapsed = 0
        while elapsed < total_sec and not shutdown_event.is_set():
            step = min(60, total_sec - elapsed)
            if shutdown_event.wait(timeout=step):
                return
            elapsed += step
        if shutdown_event.is_set():
            return
        try:
            log.info("Starting scheduled model retrain (train_model.py)...")
            result = subprocess.run(
                [sys.executable, "train_model.py"],
                capture_output=True,
                text=True,
                timeout=3600,
            )
            if result.returncode == 0:
                log.info("Retrain finished OK; reloading model in memory")
                reload_model()
            else:
                log.error("Retrain failed (exit %s):\n%s", result.returncode, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Retrain subprocess exceeded 1 hour timeout")
        except Exception as e:
            log.error("Retrain error: %s", e)


def collect_and_predict():
    log.info("Collector + predictor loop started (interval=%ss)", INTERVAL)
    if config.get("data_retention", {}).get("enabled", True):
        cleanup_old_data(days=RETENTION_DAYS)

    cleanup_counter = 0
    while not shutdown_event.is_set():
        try:
            collected = collect_all(on_timeout=on_timeout)
            anomalies = predict_all(collected)

            if anomalies:
                for anomaly in anomalies:
                    try:
                        if client.is_ready():
                            asyncio.run_coroutine_threadsafe(anomaly_queue.put(anomaly), client.loop)
                    except Exception as e:
                        log.error("Failed to queue anomaly for Discord: %s", e)

                    push_anomaly(
                        {
                            "device": anomaly["device"],
                            "intf": anomaly["intf"],
                            "ip": anomaly.get("ip", "N/A"),
                            "label": anomaly["prediction"],
                            "is_device_down": anomaly.get("is_device_down", False),
                            "detection_source": anomaly.get("detection_source"),
                            "severity": anomaly.get("severity"),
                            "correlated_with": anomaly.get("correlated_with"),
                        }
                    )
                log.info("Reported %s anomaly row(s)", len(anomalies))
            else:
                log.info("All interfaces OK (Rules OK, AI OK)")

            cleanup_counter += 1
            if cleanup_counter * INTERVAL >= 3600:
                if config.get("data_retention", {}).get("enabled", True):
                    cleanup_old_data(days=RETENTION_DAYS)
                cleanup_counter = 0

        except Exception as e:
            log.error("Collect/Predict error: %s", e)

        # Wait for interval OR early wakeup from remediation
        collect_now_event.clear()
        # Use short sleep steps so collect_now_event can wake us early
        waited = 0
        while waited < INTERVAL:
            if shutdown_event.is_set():
                break
            if collect_now_event.wait(timeout=min(2, INTERVAL - waited)):
                collect_now_event.clear()
                log.info("Early collect triggered (post-remediation)")
                break
            waited += 2
        if shutdown_event.is_set():
            break

    log.info("Collector + predictor loop stopped")


def signal_handler(sig, frame):
    try:
        signame = signal.Signals(sig).name
    except (ValueError, AttributeError):
        signame = str(sig)
    log.info("Received %s — shutting down...", signame)
    request_shutdown()
    _stop_discord_gracefully()
    syslog_server_instance.stop()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=" * 50)
    print("  NetSentinel AI — Network Monitor v2")
    print("=" * 50)

    init_db()
    syslog_server_instance.start()

    t_collect = threading.Thread(target=collect_and_predict, name="collect_predict", daemon=True)
    t_collect.start()

    t_dashboard = threading.Thread(target=run_dashboard, name="dashboard", daemon=True)
    t_dashboard.start()

    t_retrain = threading.Thread(target=auto_retrain_loop, name="auto_retrain", daemon=True)
    t_retrain.start()

    log.info("Discord bot starting (if DISCORD_TOKEN is set)...")
    log.info("Dashboard: http://localhost:5000")

    try:
        run_bot()
    except Exception as e:
        log.error("Discord bot stopped: %s", e)

    if not shutdown_event.is_set():
        log.info("Discord inactive or disconnected; collector/dashboard still running. Press Ctrl+C to stop.")
        try:
            while not shutdown_event.wait(60):
                pass
        except KeyboardInterrupt:
            request_shutdown()

    request_shutdown()
    syslog_server_instance.stop()
    log.info("Waiting for collector thread (max 90s)...")
    t_collect.join(timeout=90)
    if t_collect.is_alive():
        log.warning("Collector thread still alive after join timeout")

    log.info("NetSentinel shutdown complete")
    sys.exit(0)

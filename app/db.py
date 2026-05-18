# นำเข้าไลบรารีที่จำเป็นสำหรับจัดการฐานข้อมูล
from sqlalchemy import create_engine, text  # ไลบรารีสำหรับจัดการฐานข้อมูล SQL
from datetime import datetime  # สำหรับจัดการวันที่และเวลา
import yaml  # สำหรับอ่านไฟล์การตั้งค่า
import logging
import os
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

# อ่านไฟล์การตั้งค่าจาก config.yaml
with open('config/config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# สร้างการเชื่อมต่อกับฐานข้อมูล MySQL — อ่าน URL จาก .env
DB_URL = os.getenv('DB_URL', config.get('database', {}).get('url', ''))
engine = create_engine(
    DB_URL,
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,
    pool_pre_ping=True
)

def init_db():
    """ฟังก์ชันสำหรับเริ่มต้นฐานข้อมูล สร้างตารางที่จำเป็น"""
    with engine.connect() as conn:
        # สร้างตาราง interface_logs สำหรับเก็บข้อมูล interface
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS interface_logs (
                id             INT AUTO_INCREMENT PRIMARY KEY,
                device_name    VARCHAR(50),
                interface_name VARCHAR(50),
                ip_address     VARCHAR(20),
                status         VARCHAR(20),
                protocol       VARCHAR(20),
                reliability    INT DEFAULT 255,
                network_load   INT DEFAULT 1,
                rxload         INT DEFAULT 1,
                input_errors   INT DEFAULT 0,
                link_type      VARCHAR(20),
                zone           VARCHAR(20),
                location       VARCHAR(50),
                collected_at   DATETIME,
                created_at     TIMESTAMP DEFAULT current_timestamp(),
                label          VARCHAR(10)
            )
        """))
        # สร้างตาราง ai_predictions สำหรับเก็บผลการทำนายของ AI
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS ai_predictions (
                id               INT AUTO_INCREMENT PRIMARY KEY,
                log_id           INT,
                device_name      VARCHAR(50),
                interface_name   VARCHAR(50),
                prediction_label VARCHAR(50),
                confidence_score FLOAT,
                detection_source VARCHAR(32) NULL,
                is_fixed         BOOLEAN DEFAULT FALSE,
                fixed_at         DATETIME,
                predicted_at     DATETIME,
                FOREIGN KEY (log_id) REFERENCES interface_logs(id)
            )
        """))
        # สร้างตาราง devices สำหรับเก็บข้อมูลอุปกรณ์
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS devices (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                name        VARCHAR(50) UNIQUE,
                host        VARCHAR(50),
                device_type VARCHAR(50),
                username    VARCHAR(50),
                password    VARCHAR(50),
                secret      VARCHAR(50),
                location    VARCHAR(50),
                zone        VARCHAR(20),
                is_active   BOOLEAN DEFAULT TRUE,
                created_at  TIMESTAMP DEFAULT current_timestamp()
            )
        """))

        # ── สร้าง Indexes เพื่อเพิ่มความเร็ว query ──────────────────────
        index_statements = [
            "CREATE INDEX idx_logs_device_intf_time ON interface_logs(device_name, interface_name, collected_at)",
            "CREATE INDEX idx_logs_label ON interface_logs(label)",
            "CREATE INDEX idx_logs_collected_at ON interface_logs(collected_at)",
            "CREATE INDEX idx_pred_label_date ON ai_predictions(prediction_label, predicted_at)",
            "CREATE INDEX idx_pred_log_id ON ai_predictions(log_id)",
        ]
        for stmt in index_statements:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass  # index อาจมีอยู่แล้ว

        conn.commit()
    _migrate_ai_predictions_detection_source()
    log.info("Database initialized with indexes")


def _migrate_ai_predictions_detection_source():
    """เพิ่มคอลัมน์ detection_source สำหรับฐานข้อมูลที่สร้างจากสคีมาเก่า"""
    try:
        with engine.connect() as conn:
            conn.execute(text(
                "ALTER TABLE ai_predictions ADD COLUMN detection_source VARCHAR(32) NULL"
            ))
            conn.commit()
    except Exception:
        pass


def cleanup_old_data(days=30):
    """ลบข้อมูลเก่ากว่า N วัน เพื่อไม่ให้ DB บวม"""
    try:
        with engine.connect() as conn:
            # ลบ predictions เก่า
            result1 = conn.execute(text("""
                DELETE FROM ai_predictions
                WHERE predicted_at < DATE_SUB(NOW(), INTERVAL :days DAY)
            """), {"days": days})

            # ลบ logs เก่าที่ไม่มี prediction อ้างอิง
            result2 = conn.execute(text("""
                DELETE FROM interface_logs
                WHERE collected_at < DATE_SUB(NOW(), INTERVAL :days DAY)
                  AND id NOT IN (SELECT log_id FROM ai_predictions)
            """), {"days": days})

            conn.commit()
            total = result1.rowcount + result2.rowcount
            if total > 0:
                log.info(f"Cleanup: ลบข้อมูลเก่า {total} records (>{days} วัน)")
    except Exception as e:
        log.error(f"Cleanup error: {e}")


def get_analytics():
    with engine.connect() as conn:

        # 1. สรุป anomaly ทั้งหมด
        anomaly_summary = conn.execute(text("""
            SELECT 
                COUNT(*) as total_logs,
                SUM(label = 'anomaly') as total_anomaly,
                SUM(label = 'normal')  as total_normal,
                ROUND(SUM(label = 'anomaly') / COUNT(*) * 100, 1) as anomaly_pct
            FROM interface_logs
        """)).fetchone()

        # 2. anomaly วันนี้
        anomaly_today = conn.execute(text("""
            SELECT COUNT(*) as today_anomaly
            FROM ai_predictions
            WHERE prediction_label = 'anomaly'
              AND DATE(predicted_at) = CURDATE()
        """)).fetchone()

        # 3. fix rate
        fix_rate = conn.execute(text("""
            SELECT 
                COUNT(*)                                    as total_anomaly,
                SUM(is_fixed = 1)                           as total_fixed,
                ROUND(SUM(is_fixed = 1) / COUNT(*) * 100, 1) as fix_rate_pct
            FROM ai_predictions
            WHERE prediction_label = 'anomaly'
        """)).fetchone()

        # 4. top 5 device ที่มีปัญหาเยอะสุด
        top_devices = conn.execute(text("""
            SELECT device_name, COUNT(*) as anomaly_count
            FROM ai_predictions
            WHERE prediction_label = 'anomaly'
            GROUP BY device_name
            ORDER BY anomaly_count DESC
            LIMIT 5
        """)).fetchall()

        # 5. top 5 interface ที่มีปัญหาเยอะสุด
        top_interfaces = conn.execute(text("""
            SELECT device_name, interface_name, COUNT(*) as anomaly_count
            FROM ai_predictions
            WHERE prediction_label = 'anomaly'
            GROUP BY device_name, interface_name
            ORDER BY anomaly_count DESC
            LIMIT 5
        """)).fetchall()

        # 6. uptime แต่ละ device (% ของเวลาที่ normal)
        uptime = conn.execute(text("""
            SELECT 
                device_name,
                ROUND(SUM(label = 'normal') / COUNT(*) * 100, 1) as uptime_pct,
                COUNT(*) as total_records
            FROM interface_logs
            GROUP BY device_name
            ORDER BY device_name
        """)).fetchall()

        # 7. traffic trend รายชั่วโมง (6 ชั่วโมงล่าสุด)
        traffic_trend = conn.execute(text("""
            SELECT 
                DATE_FORMAT(collected_at, '%H:00') as hour,
                ROUND(AVG(network_load), 1)        as avg_load,
                MAX(network_load)                  as max_load,
                COUNT(*)                           as records
            FROM interface_logs
            WHERE collected_at >= DATE_SUB(NOW(), INTERVAL 6 HOUR)
            GROUP BY DATE_FORMAT(collected_at, '%H:00')
            ORDER BY hour ASC
        """)).fetchall()

        # 8. anomaly by type
        anomaly_by_type = conn.execute(text("""
            SELECT 
                status, protocol,
                COUNT(*) as count
            FROM interface_logs
            WHERE label = 'anomaly'
            GROUP BY status, protocol
            ORDER BY count DESC
        """)).fetchall()

        return {
            'summary'         : anomaly_summary,
            'today'           : anomaly_today,
            'fix_rate'        : fix_rate,
            'top_devices'     : top_devices,
            'top_interfaces'  : top_interfaces,
            'uptime'          : uptime,
            'traffic_trend'   : traffic_trend,
            'anomaly_by_type' : anomaly_by_type
        }


def save_log(device, intf, ip, status, proto, rel, tx, rx, err, ltype, zone, location, label):
    now = datetime.now()
    with engine.connect() as conn:
        result = conn.execute(text("""
            INSERT INTO interface_logs
            (device_name, interface_name, ip_address, status, protocol,
             reliability, network_load, rxload, input_errors, link_type,
             zone, location, collected_at, created_at, label)
            VALUES (:device, :intf, :ip, :status, :proto,
                    :rel, :load, :rx, :err, :ltype,
                    :zone, :location, :now, :now, :label)
        """), {
            "device": device, "intf": intf, "ip": ip,
            "status": status, "proto": proto,
            "rel": rel, "load": tx, "rx": rx, "err": err,
            "ltype": ltype, "zone": zone, "location": location,
            "now": now, "label": label
        })
        conn.commit()
        return result.lastrowid

def save_prediction(log_id, device, intf, prediction, confidence, detection_source=None):
    with engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO ai_predictions
            (log_id, device_name, interface_name, prediction_label,
             confidence_score, detection_source, predicted_at)
            VALUES (:log_id, :device, :intf, :label, :score, :src, :now)
        """), {
            "log_id": log_id, "device": device, "intf": intf,
            "label": prediction, "score": confidence,
            "src": detection_source,
            "now": datetime.now()
        })
        conn.commit()

def get_anomaly_history(limit=10):
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT p.predicted_at, p.device_name, p.interface_name,
                    p.prediction_label, p.confidence_score, p.is_fixed,
                    l.status, l.protocol, l.network_load, l.rxload,
                    p.detection_source
            FROM ai_predictions p
            JOIN interface_logs l ON p.log_id = l.id
            WHERE p.prediction_label = 'anomaly'
            ORDER BY p.predicted_at DESC
            LIMIT :limit
        """), {"limit": limit})
        return result.fetchall()

def mark_as_fixed(log_id):
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE ai_predictions
            SET is_fixed = TRUE, fixed_at = :now
            WHERE log_id = :log_id
        """), {"log_id": log_id, "now": datetime.now()})
        conn.commit()

def get_device_status():
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT l.device_name, l.interface_name, l.ip_address,
                    l.status, l.protocol, l.network_load, l.rxload,
                    l.reliability, l.label, l.collected_at
            FROM interface_logs l
            INNER JOIN (
                SELECT device_name, interface_name, MAX(collected_at) as max_time
                FROM interface_logs
                GROUP BY device_name, interface_name
            ) latest ON l.device_name = latest.device_name
                    AND l.interface_name = latest.interface_name
                    AND l.collected_at = latest.max_time
            ORDER BY l.device_name, l.interface_name
        """))
        return result.fetchall()
import socket
import threading
import logging
import re
from datetime import datetime
from sqlalchemy import text
from app.db import engine

log = logging.getLogger(__name__)

# Intelligent AI lookup dictionary containing explanations and troubleshooting recommendations
CISCO_MNEMONICS_TH = {
    "LINK": {
        "CHANGED": (
            "อินเทอร์เฟซทางกายภาพมีการเปลี่ยนแปลงสถานะการทำงาน (เช่น มีการดึงสาย LAN ออก, อุปกรณ์ปลายทางถูกปิดเครื่อง, หรือพอร์ตถูกสั่ง Shutdown)",
            "1. ตรวจสอบสายเชื่อมต่อทางกายภาพที่พอร์ต\n2. ตรวจสอบสถานะการจ่ายไฟและการเชื่อมต่อของอุปกรณ์ปลายทาง\n3. พิมพ์คำสั่ง 'no shutdown' บนพอร์ตหากเป็นการปิดชั่วคราวโดยแอดมิน"
        )
    },
    "LINEPROTO": {
        "UPDOWN": (
            "โปรโตคอลการทำงานบนสายสัญญาณเปลี่ยนสถานะ (Line Protocol) มักเกิดตามหลังลิงก์ทางกายภาพ หรือมีความไม่สอดคล้องของการตั้งค่าพอร์ต",
            "1. ตรวจสอบสถานะสายเชื่อมโยงทางกายภาพ\n2. ตรวจสอบความถูกต้องของการตั้งค่า encapsulation ทั้งสองฝั่ง\n3. ตรวจสอบว่า VLAN หรือโหมดพอร์ต (Access/Trunk) สอดคล้องตรงกัน"
        )
    },
    "OSPF": {
        "ADJCHG": (
            "ความสัมพันธ์เพื่อนบ้านของโปรโตคอลการจัดเส้นทาง OSPF (Neighbor Adjacency) มีการเปลี่ยนแปลงสถานะ (เช่น เพื่อนบ้านหลุด OSPF Neighbor DOWN)",
            "1. ตรวจสอบการเชื่อมโยง IP ไปยังเพื่อนบ้านว่าปิงเจอกันปกติหรือไม่\n2. ตรวจสอบ Hello/Dead Timer, Area ID และ Subnet Mask ให้มีค่าตรงกันทั้งสองฝั่ง\n3. ตรวจสอบและยกเลิกนโยบายไฟร์วอลล์ที่ปิดกั้นแพ็กเก็ต OSPF Multicast"
        )
    },
    "SYS": {
        "CONFIG_I": (
            "มีการแก้ไขหรือเปลี่ยนแปลงรายละเอียดการตั้งค่า (Configuration) ของอุปกรณ์เครือข่ายผ่านทางหน้าจอ Terminal/Console",
            "1. ตรวจสอบว่าแอดมินหรือผู้ใช้ที่เกี่ยวข้องตั้งใจเข้ามาทำการเปลี่ยนการตั้งค่าหรือไม่\n2. ตรวจสอบประวัติการรันคำสั่ง (Audit logs) เพื่อดูความเสี่ยง\n3. ควรกดสำรองข้อมูลอุปกรณ์ทันที (Run Backup) เพื่ออัปเดตไฟล์คอนฟิกล่าสุด"
        )
    },
    "SEC": {
        "IPACCESSLOGP": (
            "ตรวจพบแพ็กเก็ตข้อมูลที่โดนสกัดกั้นหรือตรวจสอบโดยนโยบายความปลอดภัยของ Access Control List (ACL)",
            "1. ตรวจสอบหมายเลข IP ต้นทางเพื่อเช็กพฤติกรรมการแอบแสกนข้อมูลหรือเข้าถึงโดยไม่ได้รับอนุญาต\n2. ตรวจสอบนโยบายความถูกต้องของกฎ ACL ว่าเข้มงวดเกินไปจนบล็อกผู้ใช้ปกติหรือไม่"
        )
    },
    "IP": {
        "DUPADDR": (
            "ตรวจพบหมายเลขไอพีแอดเดรสชนกัน (Duplicate IP Address) ในระบบเครือข่าย ส่งผลให้อุปกรณ์ที่ไอพีชนกันใช้งานเครือข่ายไม่ได้",
            "1. ค้นหาหมายเลข MAC Address ของไอพีที่แจ้งเตือนชนกันเพื่อระบุยี่ห้อและอุปกรณ์\n2. ค้นหาพอร์ตสวิตช์ปลายทางที่เชื่อมต่ออยู่ และทำการสั่งปิดพอร์ตชั่วคราวเพื่อแยกแยะ\n3. ตั้งค่าหมายเลข IP แอดเดรสใหม่ให้กับตัวปัญหาเพื่อหลีกเลี่ยงการชนกัน"
        )
    }
}

SEVERITIES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug"
}

def analyze_syslog_ai(facility, mnemonic, message):
    """Analyze the syslog entry using a heuristic lookup to generate detailed Thai root causes and recommendations."""
    fac = (facility or "").upper()
    mnem = (mnemonic or "").upper()
    
    # Check if mnemonic exists in dictionary
    if fac in CISCO_MNEMONICS_TH and mnem in CISCO_MNEMONICS_TH[fac]:
        return CISCO_MNEMONICS_TH[fac][mnem]
    
    # Check general mnemonic fallback
    for f_key, mnems in CISCO_MNEMONICS_TH.items():
        if mnem in mnems:
            return mnems[mnem]
            
    # Generic fallback based on key terms
    msg_upper = message.upper()
    if "DUPLICATE" in msg_upper or "DUP" in msg_upper:
        return CISCO_MNEMONICS_TH["IP"]["DUPADDR"]
    if "SHUTDOWN" in msg_upper or "ADMINISTRATIVELY DOWN" in msg_upper:
        return (
            "อินเทอร์เฟซพอร์ตเครือข่ายถูกสั่งปิดการทำงานแบบจงใจ (Shutdown) หรือแอดมินแก้ไขค่าระบบ",
            "1. หากเป็นการปิดปรับปรุง ให้ดำเนินการต่อตามรอบเวลาซ่อมบำรุง\n2. ตรวจสอบสิทธิ์ผู้ดูแลระบบที่เข้ามาสั่งชัตดาวน์พอร์ต\n3. ใช้คำสั่ง 'no shutdown' เพื่อเปิดใช้งานพอร์ตอีกครั้ง"
        )
    if "COLLISION" in msg_upper or "LATE COLLISION" in msg_upper:
        return (
            "เกิดการชนกันของสัญญาณข้อมูลบนสายส่ง (Duplex Collision) มักเกิดจากการตั้งค่าความเร็วสายไม่ตรงกัน",
            "1. ตรวจสอบการตั้งค่าความเร็วของพอร์ต (Speed/Duplex) ทั้งสองฝั่งให้ออโต้ตรงกัน\n2. ตรวจสอบคุณภาพสายสัญญาณกายภาพว่าหักหรืองอจนเกิดสายรั่วหรือไม่"
        )
        
    return (
        f"เกิดเหตุการณ์ประเภท {fac} รหัส [{mnem}] บนระบบเครือข่าย รายละเอียดข้อความ: {message}",
        "1. ค้นหารายละเอียดคำสั่งสากลจากรหัสเหตุการณ์เพื่อประเมินระดับความเสียหาย\n2. ใช้กล่องเครื่องมือปัญญาประดิษฐ์ (AI Sandbox) ด้านบนเพื่อตรวจสอบพารามิเตอร์นี้ในขั้นถัดไป"
    )

class SyslogUDPHandler:
    def __init__(self, host="0.0.0.0", port=514):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            log.info(f"🟢 Syslog server started successfully on UDP port {self.port}")
        except PermissionError:
            # Fallback to port 5140 if port 514 is restricted
            alt_port = 5140
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.bind((self.host, alt_port))
                self.port = alt_port
                log.info(f"🟡 Port 514 blocked (permission). Fallback Syslog server started on UDP port {self.port}")
            except Exception as e:
                log.error(f"❌ Failed to bind syslog fallback socket: {e}")
                self.running = False
                return
        except Exception as e:
            log.error(f"❌ Failed to bind syslog socket: {e}")
            self.running = False
            return

        self.thread = threading.Thread(target=self._listen, daemon=True, name="syslog_listener")
        self.thread.start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        log.info("🔴 Syslog server stopped")

    def _listen(self):
        buffer_size = 4096
        while self.running:
            try:
                data, addr = self.sock.recvfrom(buffer_size)
                if not data:
                    continue
                
                # Parse message in separate thread to prevent socket clogging
                threading.Thread(target=self._parse_and_save, args=(data.decode("utf-8", errors="ignore"), addr[0]), daemon=True).start()
            except Exception as e:
                if self.running:
                    log.debug(f"Syslog recv error: {e}")

    def _parse_and_save(self, raw_msg, sender_ip):
        try:
            # Resolve device name from database
            device_name = "Unknown"
            try:
                with engine.connect() as conn:
                    dev = conn.execute(
                        text("SELECT name FROM devices WHERE host = :ip LIMIT 1"),
                        {"ip": sender_ip}
                    ).fetchone()
                    if dev:
                        device_name = dev[0]
            except Exception as e:
                log.debug(f"Syslog device lookup failed: {e}")

            # Parse PRI header (RFC 3164 / 5424)
            pri = 13  # Default facility user, severity notice
            message = raw_msg
            pri_match = re.match(r"^<(\d+)>(.*)", raw_msg)
            if pri_match:
                pri = int(pri_match.group(1))
                message = pri_match.group(2)

            facility_code = pri // 8
            severity_code = pri % 8
            severity = SEVERITIES.get(severity_code, "Notice")

            # Extract timestamp, sequence, or header boilerplate
            # Cisco syslogs usually contain: "82: *May 24 16:45:29.812: %LINK-5-CHANGED: Message text"
            cisco_pattern = r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):\s*(.*)"
            cisco_match = re.search(cisco_pattern, message)

            if cisco_match:
                facility = cisco_match.group(1)
                mnemonic = cisco_match.group(3)
                log_message = cisco_match.group(4).strip()
            else:
                facility = "SYS"
                mnemonic = "GENERIC"
                log_message = message.strip()

            # AI Semantic Root Cause / Recommendation Heuristics
            ai_cause, ai_suggestion = analyze_cause_on_the_fly(facility, mnemonic, log_message)

            received_at = datetime.now()

            # Save in database
            with engine.connect() as conn:
                conn.execute(
                    text("""
                        INSERT INTO device_syslogs 
                        (device_name, ip_address, facility, severity, mnemonic, message, ai_cause, ai_suggestion, received_at)
                        VALUES (:dev, :ip, :fac, :sev, :mnem, :msg, :cause, :sugg, :recv)
                    """),
                    {
                        "dev": device_name,
                        "ip": sender_ip,
                        "fac": facility,
                        "sev": severity,
                        "mnem": mnemonic,
                        "msg": log_message,
                        "cause": ai_cause,
                        "sugg": ai_suggestion,
                        "recv": received_at
                    }
                )
                conn.commit()

            # Live broadcast over Socket.IO (lazy imports to avoid circular deps)
            try:
                from web.dashboard import socketio
                socketio.emit("syslog_received", {
                    "device_name": device_name,
                    "ip_address": sender_ip,
                    "facility": facility,
                    "severity": severity,
                    "mnemonic": mnemonic,
                    "message": log_message,
                    "ai_cause": ai_cause,
                    "ai_suggestion": ai_suggestion,
                    "received_at": received_at.strftime("%Y-%m-%d %H:%M:%S")
                })
            except Exception as se:
                log.debug(f"Syslog socketio broadcast failed: {se}")

        except Exception as e:
            log.error(f"Syslog parse error: {e}")

def analyze_cause_on_the_fly(facility, mnemonic, message):
    """Helper wrapping the main analyzer with robust default safeguards."""
    try:
        return analyze_syslog_ai(facility, mnemonic, message)
    except Exception:
        return ("ไม่สามารถระบุสาเหตุทางปัญญาประดิษฐ์ย้อนหลังได้สำเร็จ", "1. แนะนำให้เชื่อมโยงข้อมูล CLI เพิ่มเติมเพื่อตรวจสอบประเด็นนี้")

# Global singleton syslog server object
syslog_server_instance = SyslogUDPHandler()

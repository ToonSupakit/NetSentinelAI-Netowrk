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

CISCO_MNEMONICS_EN = {
    "LINK": {
        "CHANGED": (
            "The physical interface changed state. Common causes include a disconnected cable, a powered-off peer device, or an administratively shut down port.",
            "1. Check the physical cable and transceiver at the port\n2. Verify power and link state on the peer device\n3. Run 'no shutdown' on the interface if it was disabled intentionally"
        )
    },
    "LINEPROTO": {
        "UPDOWN": (
            "The line protocol changed state. This usually follows a physical link change or a mismatch in interface configuration.",
            "1. Check the physical link state\n2. Verify encapsulation settings on both ends\n3. Confirm VLAN and access/trunk mode match on both sides"
        )
    },
    "OSPF": {
        "ADJCHG": (
            "The OSPF neighbor adjacency changed state, such as a neighbor going down or re-forming.",
            "1. Verify IP reachability to the neighbor\n2. Check Hello/Dead timers, Area ID, and subnet mask on both sides\n3. Make sure firewall or ACL rules are not blocking OSPF multicast packets"
        )
    },
    "SYS": {
        "CONFIG_I": (
            "The device configuration was changed through a terminal or console session.",
            "1. Confirm whether the change was expected\n2. Review command and audit history for risk\n3. Run a fresh configuration backup so the latest running config is captured"
        )
    },
    "SEC": {
        "IPACCESSLOGP": (
            "A packet matched an Access Control List security policy and was logged or blocked.",
            "1. Review the source IP for scanning or unauthorized access attempts\n2. Check whether the ACL is too strict and blocking normal traffic"
        )
    },
    "IP": {
        "DUPADDR": (
            "A duplicate IP address was detected on the network, which can break connectivity for devices using that address.",
            "1. Find the MAC address using the duplicate IP\n2. Locate the switch port connected to that MAC address\n3. Assign a unique IP address to the conflicting device"
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

def analyze_syslog_ai(facility, mnemonic, message, lang="th"):
    """Analyze the syslog entry using a heuristic lookup in Thai or English."""
    fac = (facility or "").upper()
    mnem = (mnemonic or "").upper()
    lookup = CISCO_MNEMONICS_EN if lang == "en" else CISCO_MNEMONICS_TH
    
    # Check if mnemonic exists in dictionary
    if fac in lookup and mnem in lookup[fac]:
        return lookup[fac][mnem]
    
    # Check general mnemonic fallback
    for f_key, mnems in lookup.items():
        if mnem in mnems:
            return mnems[mnem]
            
    # Generic fallback based on key terms
    msg_upper = message.upper()
    if "DUPLICATE" in msg_upper or "DUP" in msg_upper:
        return lookup["IP"]["DUPADDR"]
    if "SHUTDOWN" in msg_upper or "ADMINISTRATIVELY DOWN" in msg_upper:
        if lang == "en":
            return (
                "The network interface was intentionally shut down, or an administrator changed the port state.",
                "1. If this is planned maintenance, continue with the maintenance window\n2. Verify which administrator changed the port state\n3. Use 'no shutdown' to bring the interface back up"
            )
        return (
            "อินเทอร์เฟซพอร์ตเครือข่ายถูกสั่งปิดการทำงานแบบจงใจ (Shutdown) หรือแอดมินแก้ไขค่าระบบ",
            "1. หากเป็นการปิดปรับปรุง ให้ดำเนินการต่อตามรอบเวลาซ่อมบำรุง\n2. ตรวจสอบสิทธิ์ผู้ดูแลระบบที่เข้ามาสั่งชัตดาวน์พอร์ต\n3. ใช้คำสั่ง 'no shutdown' เพื่อเปิดใช้งานพอร์ตอีกครั้ง"
        )
    if "COLLISION" in msg_upper or "LATE COLLISION" in msg_upper:
        if lang == "en":
            return (
                "A duplex collision was detected on the link, often caused by speed or duplex mismatch.",
                "1. Check speed and duplex settings on both ends and align them\n2. Inspect the physical cable for damage or poor termination"
            )
        return (
            "เกิดการชนกันของสัญญาณข้อมูลบนสายส่ง (Duplex Collision) มักเกิดจากการตั้งค่าความเร็วสายไม่ตรงกัน",
            "1. ตรวจสอบการตั้งค่าความเร็วของพอร์ต (Speed/Duplex) ทั้งสองฝั่งให้ออโต้ตรงกัน\n2. ตรวจสอบคุณภาพสายสัญญาณกายภาพว่าหักหรืองอจนเกิดสายรั่วหรือไม่"
        )

    if lang == "en":
        return (
            f"Network event {fac} [{mnem}] was reported. Message detail: {message}",
            "1. Look up the vendor event code to assess impact\n2. Use the AI Log Analyzer with related CLI output for deeper investigation"
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
        self.received_count = 0
        self.started_at = None
        self.bind_error = None

    def start(self):
        self.running = True
        self.bind_error = None
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            log.info(f"🟢 Syslog server started successfully on UDP port {self.port}")
        except (PermissionError, OSError) as orig_err:
            # Fallback to port 5140 if port 514 is restricted
            alt_port = 5140
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.bind((self.host, alt_port))
                self.port = alt_port
                self.bind_error = f"Port 514 blocked ({orig_err}). Using fallback port {alt_port}"
                log.info(f"🟡 {self.bind_error}")
            except Exception as e:
                self.bind_error = f"Failed to bind any syslog port: {e}"
                log.error(f"❌ {self.bind_error}")
                self.running = False
                return
        except Exception as e:
            self.bind_error = f"Failed to bind syslog socket: {e}"
            log.error(f"❌ {self.bind_error}")
            self.running = False
            return

        self.started_at = datetime.now()
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

    def get_status(self):
        """Return a dict summarizing the current state of the syslog server."""
        return {
            "running": self.running,
            "port": self.port,
            "host": self.host,
            "received_count": self.received_count,
            "started_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else None,
            "bind_error": self.bind_error,
        }

    def send_test(self):
        """Send a fake Cisco-style syslog message to ourselves for verification."""
        test_msg = "<189>1: *Test: %SYS-5-CONFIG_I: Configured from console by NetSentinel_Test"
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.sendto(test_msg.encode("utf-8"), ("127.0.0.1", self.port))
            test_sock.close()
            return True, f"Test syslog sent to 127.0.0.1:{self.port}"
        except Exception as e:
            return False, str(e)

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
            self.received_count += 1
            # Resolve device name from config/devices.yaml or fallback to database
            device_name = "Unknown"
            try:
                import yaml
                with open("config/devices.yaml", "r", encoding="utf-8") as f:
                    dev_conf = yaml.safe_load(f)
                    for d in dev_conf.get("devices", []):
                        if d.get("host") == sender_ip:
                            device_name = d.get("name", "Unknown")
                            break
            except Exception as yaml_err:
                log.debug(f"Syslog device lookup from yaml failed: {yaml_err}")

            if device_name == "Unknown":
                try:
                    with engine.connect() as conn:
                        dev = conn.execute(
                            text("SELECT name FROM devices WHERE host = :ip LIMIT 1"),
                            {"ip": sender_ip}
                        ).fetchone()
                        if dev:
                            device_name = dev[0]
                except Exception as e:
                    log.debug(f"Syslog device lookup from db failed: {e}")

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

            # If syslog is a Cisco LINK/LINEPROTO status change, immediately update interface_logs
            if facility in ("LINK", "LINEPROTO") and mnemonic in ("CHANGED", "UPDOWN"):
                status_match = re.search(r"Interface\s+([A-Za-z0-9/\.\-]+),\s+changed\s+state\s+to\s+([a-z\s_]+)", log_message, re.IGNORECASE)
                if status_match:
                    intf_name = status_match.group(1).strip()
                    raw_status = status_match.group(2).strip().lower()
                    
                    status_val = "up" if "up" in raw_status else "down"
                    if "administratively down" in raw_status or "admin" in raw_status:
                        status_val = "admin_down"
                    
                    label_val = "normal" if status_val == "up" else "anomaly"
                    
                    try:
                        with engine.connect() as db_conn:
                            latest_info = db_conn.execute(
                                text("""
                                    SELECT ip_address, reliability, network_load, rxload, input_errors, link_type, zone, location 
                                    FROM interface_logs 
                                    WHERE device_name = :dev AND interface_name = :intf 
                                    ORDER BY collected_at DESC LIMIT 1
                                """),
                                {"dev": device_name, "intf": intf_name}
                            ).fetchone()
                            
                            if latest_info:
                                ip_address, reliability, network_load, rxload, input_errors, link_type, zone, location = latest_info
                                
                                log_id = db_conn.execute(
                                    text("""
                                        INSERT INTO interface_logs 
                                        (device_name, interface_name, ip_address, status, protocol, reliability, network_load, rxload, input_errors, link_type, zone, location, label, collected_at, created_at)
                                        VALUES (:dev, :intf, :ip, :status, :proto, :rel, :load, :rx, :err, :ltype, :zone, :loc, :label, :now, :now)
                                    """),
                                    {
                                        "dev": device_name,
                                        "intf": intf_name,
                                        "ip": ip_address,
                                        "status": status_val,
                                        "proto": status_val,
                                        "rel": reliability,
                                        "load": network_load,
                                        "rx": rxload,
                                        "err": input_errors,
                                        "ltype": link_type,
                                        "zone": zone,
                                        "loc": location,
                                        "label": label_val,
                                        "now": datetime.now()
                                    }
                                ).lastrowid
                                
                                if label_val == "anomaly":
                                    db_conn.execute(
                                        text("""
                                            INSERT INTO ai_predictions 
                                            (log_id, device_name, interface_name, prediction_label, confidence_score, detection_source, severity, predicted_at)
                                            VALUES (:log_id, :dev, :intf, 'anomaly', 1.0, 'syslog', :sev, :now)
                                        """),
                                        {
                                            "log_id": log_id,
                                            "dev": device_name,
                                            "intf": intf_name,
                                            "sev": "High" if status_val == "down" else "Medium",
                                            "now": datetime.now()
                                        }
                                    )
                                    
                                    try:
                                        from web.dashboard import socketio
                                        socketio.emit("anomaly", {
                                            "device": device_name,
                                            "intf": intf_name,
                                            "ip": ip_address,
                                            "prediction": "anomaly",
                                            "is_device_down": False,
                                            "detection_source": "syslog",
                                            "severity": "High" if status_val == "down" else "Medium"
                                        })
                                    except Exception as sock_err:
                                        log.debug(f"Syslog immediate socket emit failed: {sock_err}")
                                else:
                                    db_conn.execute(
                                        text("""
                                            UPDATE ai_predictions 
                                            SET is_fixed = 1, fixed_at = :now 
                                            WHERE device_name = :dev AND interface_name = :intf AND prediction_label = 'anomaly' AND COALESCE(is_fixed, 0) = 0
                                        """),
                                        {"dev": device_name, "intf": intf_name, "now": datetime.now()}
                                    )
                                db_conn.commit()
                    except Exception as db_err:
                        log.debug(f"Syslog immediate interface_logs insertion failed: {db_err}")

            # Live broadcast over Socket.IO (lazy imports to avoid circular deps)
            try:
                from web.dashboard import socketio
                ai_cause_en, ai_suggestion_en = analyze_cause_on_the_fly(facility, mnemonic, log_message, lang="en")
                socketio.emit("syslog_received", {
                    "device_name": device_name,
                    "ip_address": sender_ip,
                    "facility": facility,
                    "severity": severity,
                    "mnemonic": mnemonic,
                    "message": log_message,
                    "ai_cause": ai_cause,
                    "ai_suggestion": ai_suggestion,
                    "ai_cause_en": ai_cause_en,
                    "ai_suggestion_en": ai_suggestion_en,
                    "received_at": received_at.strftime("%Y-%m-%d %H:%M:%S")
                })
            except Exception as se:
                log.debug(f"Syslog socketio broadcast failed: {se}")

        except Exception as e:
            log.error(f"Syslog parse error: {e}")

def analyze_cause_on_the_fly(facility, mnemonic, message, lang="th"):
    """Helper wrapping the main analyzer with robust default safeguards."""
    try:
        return analyze_syslog_ai(facility, mnemonic, message, lang=lang)
    except Exception:
        if lang == "en":
            return ("AI could not identify a historical root cause for this event.", "1. Add related CLI output and inspect this event again")
        return ("ไม่สามารถระบุสาเหตุทางปัญญาประดิษฐ์ย้อนหลังได้สำเร็จ", "1. แนะนำให้เชื่อมโยงข้อมูล CLI เพิ่มเติมเพื่อตรวจสอบประเด็นนี้")

# Global singleton syslog server object
syslog_server_instance = SyslogUDPHandler()

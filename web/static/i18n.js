/**
 * NetSentinel AI - Internationalization (i18n) System
 * Centralized language management for the entire application
 * Supports: English (en) and Thai (th)
 */

const NetSentinelI18n = {
  currentLang: localStorage.getItem('netsentinel_lang') || 'en',
  observer: null,
  lastDispatchedLang: null,
  
  // Dictionary: English → Thai
  dictionary: {
    // Navigation
    "Dashboard": "แดชบอร์ด",
    "Traffic": "ทราฟฟิก",
    "Topology Map": "แผนที่เครือข่าย",
    "System Logs": "บันทึกระบบ",
    "Config Backups": "สำรองไฟล์คอนฟิก",
    "Settings": "ตั้งค่า",
    "Logout": "ออกจากระบบ",
    "Light Mode": "โหมดสว่าง",
    "Dark": "มืด",
    "Light": "สว่าง",
    "EN / TH": "EN / TH",
    "English / ไทย": "English / ไทย",
    "ภาษาไทย / EN": "ภาษาไทย / EN",

    // Dashboard
    "Status Feed": "สัญญาณสถานะ",
    "Interface Status": "สถานะอินเทอร์เฟซ",
    "Anomaly Feed": "ตัวบ่งชี้ความผิดปกติ",
    "Latest Anomalies": "ความผิดปกติล่าสุด",
    "No anomalies detected": "ไม่พบความผิดปกติ",
    "Loading status...": "กำลังโหลดสถานะ...",
    "Error loading status": "เกิดข้อผิดพลาดในการโหลดสถานะ",
    "up": "ทำงาน (up)",
    "down": "ปิดใช้งาน (down)",
    "Reliability": "ความเสถียร",
    "Load": "ปริมาณทราฟฟิก",
    "Errors": "ข้อผิดพลาด",
    "Bounce Port": "สั่งรีเซ็ตพอร์ต (Bounce)",
    "Configure Limit": "จำกัดความเร็ว",
    "Remove Limit": "ยกเลิกการจำกัด",
    "Fix": "สั่งรีเซ็ตพอร์ต (Bounce)",
    "Limit": "จำกัดความเร็ว",
    "Unlimit": "ยกเลิกการจำกัด",

    // Traffic Page
    "Traffic analytics": "การวิเคราะห์ปริมาณข้อมูล",
    "Network Traffic": "ปริมาณข้อมูลทราฟฟิกเครือข่าย",
    "Interface utilization trend from the latest collector samples.": "แนวโน้มการใช้งานอินเทอร์เฟซจากตัวอย่างล่าสุดของคอลเลกเตอร์",
    "Loading traffic...": "กำลังโหลดข้อมูลทราฟฟิก...",
    "Peak TX": "ปริมาณการส่งออกข้อมูลสูงสุด",
    "Peak RX": "ปริมาณการรับเข้าข้อมูลสูงสุด",
    "Average Load": "อัตราการดาวน์โหลดเฉลี่ย",
    "Devices": "อุปกรณ์เครือข่าย",
    "Across visible devices": "ของอุปกรณ์เครือข่ายที่พบ",
    "Last Hour Trend": "แนวโน้มปริมาณข้อมูลย้อนหลัง 1 ชั่วโมง",
    "All devices": "อุปกรณ์ทั้งหมด",
    "Both": "ทั้งส่งและรับ (Both)",
    "Top Utilization": "5 อันดับอัตราการใช้งานสูงสุด",
    "Latest Snapshot": "ภาพรวมสถานะล่าสุด",
    "Watch": "เฝ้าระวัง",
    "High": "สูงมาก",
    "No traffic data": "ไม่มีข้อมูลทราฟฟิกในขณะนี้",
    "Collector has not returned traffic samples yet.": "ระบบกำลังคัดกรองข้อมูลเครือข่ายและรอดึงตัวอย่างทราฟฟิก...",
    "Traffic unavailable": "ไม่สามารถระบุปริมาณข้อมูลได้",

    // Topology Page
    "Link Details": "รายละเอียดการเชื่อมต่อเครือข่าย",
    "Backbone Link Details": "รายละเอียดเส้นการเชื่อมต่อหลัก (Backbone Link)",
    "Link Status": "สถานะลิงก์การเชื่อมต่อ",
    "Traffic Label": "ป้ายระบุพฤติกรรมข้อมูลทราฟฟิก",
    "Device Name": "ชื่ออุปกรณ์เครือข่าย",
    "Role": "บทบาทหน้าที่อุปกรณ์",
    "Zone": "ขอบเขตการจัดตั้ง (Zone)",
    "Management Host": "ไอพีแอดเดรสสำหรับจัดการระบบ",
    "Side": "ฝั่งอุปกรณ์",
    "Interface": "ช่องอินเทอร์เฟซ",
    "IP Address": "ไอพีแอดเดรสอินเทอร์เฟซ",
    "TX Load": "ปริมาณทราฟฟิกฝั่งส่ง (TX Load)",
    "RX Load": "ปริมาณทราฟฟิกฝั่งรับ (RX Load)",
    "Fix Port": "สั่งรีเซ็ตพอร์ต (Bounce)",
    "Click nodes or links to inspect status and execute operations.": "คลิกเลือกอุปกรณ์เครือข่ายหรือสายเชื่อมต่อหลักเพื่อแสดงรายละเอียดและตัวดำเนินการ",
    "Confirm Port Bounce": "ยืนยันคำสั่ง Bounce พอร์ต",
    "Are you sure you want to fix interface": "คุณยืนยันที่จะทำการ Bounce พอร์ต",
    "on": "บนอุปกรณ์",
    "This will temporarily bounce (shutdown & no shutdown) the port.": "การดำเนินการนี้จะทำการปิดพอร์ตชั่วคราวและเปิดกลับมาใช้งานโดยทันที",
    "Yes, bounce": "ใช่, สั่ง Bounce",
    "Configure Rate Limit": "ตั้งค่าจำกัดความเร็ว (Rate Limit)",
    "Bandwidth Limit (Mbps)": "จำกัดความเร็วสูงสุดที่อนุญาต (Mbps)",
    "Auto-rollback Time (Minutes)": "รอบเวลารีเซ็ตข้อมูลความเร็วกลับมาปกติอัตโนมัติ (นาที)",
    "0 for manual removal": "ใส่ค่าเป็น 0 หากต้องการปลดเกณฑ์ความเร็วด้วยตนเอง",
    "Please enter a valid limit (1-10000 Mbps)": "โปรดระบุค่าความเร็วทราฟฟิกเครือข่ายที่ถูกต้องระหว่าง 1 ถึง 10000 Mbps",
    "Please enter a valid rollback duration": "โปรดระบุเวลาสำหรับการย้อนกลับพอร์ตให้ถูกต้อง",
    "Apply Limit": "ยืนยันจำกัดความเร็ว",

    // Logs Page
    "System Logs": "บันทึกระบบ",
    "Audit Trail": "บันทึกการตรวจสอบ",
    "No logs available": "ไม่มีบันทึกในขณะนี้",
    "Loading logs...": "กำลังโหลดบันทึก...",
    "Syslog Server: Checking...": "เซิร์ฟเวอร์ Syslog: กำลังตรวจสอบ...",
    "Syslog Server: Online": "เซิร์ฟเวอร์ Syslog: ออนไลน์",
    "Syslog Server: Offline": "เซิร์ฟเวอร์ Syslog: ออฟไลน์",
    "Syslog Server: Unreachable": "เซิร์ฟเวอร์ Syslog: ติดต่อไม่ได้",
    "Reconnecting...": "กำลังเชื่อมต่อใหม่...",
    "messages": "ข้อความ",
    "Test Syslog": "ทดสอบ Syslog",
    "Refresh": "รีเฟรช",
    "Router Configuration Guide": "คู่มือตั้งค่า Router",
    "Live Device Syslogs": "Syslog จากอุปกรณ์แบบสด",
    "All Severities": "ทุกระดับความรุนแรง",
    "Search logs...": "ค้นหา log...",
    "Reset": "รีเซ็ต",
    "Timestamp": "เวลา",
    "Device": "อุปกรณ์",
    "Severity": "ระดับ",
    "Mnemonic": "รหัสเหตุการณ์",
    "Message": "ข้อความ",
    "AI Analysis": "AI วิเคราะห์",
    "No logs found matching filters.": "ไม่พบ log ตามตัวกรอง",
    "AI Insights": "ข้อมูลวิเคราะห์ AI",
    "AI Log Analyzer": "ตัววิเคราะห์ Log ด้วย AI",
    "Paste a syslog and send it. The system will explain the likely cause and fix.": "วาง syslog แล้วกดส่ง - ระบบจะอธิบายสาเหตุและวิธีแก้",
    "Example: %LINK-3-UPDOWN, %OSPF-5-ADJCHG": "ตัวอย่าง: %LINK-3-UPDOWN, %OSPF-5-ADJCHG",
    "Tip": "คำแนะนำ",
    "Paste a log message below, then send it for analysis.": "วางข้อความ log ด้านล่าง แล้วกดปุ่มส่งเพื่อวิเคราะห์",
    "Paste syslog here...": "วาง syslog ที่นี่...",
    "Analyze log": "วิเคราะห์ log",
    "Send for analysis": "ส่งวิเคราะห์",
    "AI Log Diagnostics": "การวินิจฉัย Log ด้วย AI",
    "Original Log": "Log ต้นฉบับ",
    "Cause": "สาเหตุ",
    "Recommended Fix": "วิธีแก้ไข",
    "No unusual cause was detected.": "ไม่พบสาเหตุผิดปกติพิเศษ",
    "Check the link state and recent device events.": "ตรวจสอบสภาพการเชื่อมต่อปกติ",

    // Config Backups Page
    "Configuration Backups": "ระบบสำรองข้อมูลอุปกรณ์",
    "Automated Configuration Backups": "ระบบสำรองไฟล์คอนฟิกอุปกรณ์อัตโนมัติ",
    "Backup Session Status": "สถานะการสำรองข้อมูลในรอบปัจจุบัน",
    "Configuration Diff Engine": "เครื่องมือเปรียบเทียบความแตกต่างไฟล์คอนฟิก (Diff)",
    "Select two backup sessions below and click Compare to view running-config changes over time.": "เลือกสองเซสชันการสำรองข้อมูลด้านล่างแล้วคลิกเปรียบเทียบเพื่อดูการเปลี่ยนแปลงของรันคอนฟิก",
    "Session A": "ไฟล์สำรองตัวตั้งต้น A",
    "Session B": "ไฟล์สำรองที่จะเปรียบเทียบ B",
    "Select Device": "เลือกอุปกรณ์",
    "Compare": "เปรียบเทียบความต่าง (Diff)",
    "Historical Backup Sessions": "ประวัติการสำรองไฟล์คอนฟิกย้อนหลัง",
    "Run Backup Session": "สั่งรันสำรองข้อมูลเดี๋ยวนี้",
    "ID / TIMESTAMP": "ไอดี / วันเวลาสำรอง",
    "DEVICES BACKED UP": "จำนวนอุปกรณ์",
    "TOTAL SIZE": "ขนาดรวม",
    "VIEW FILES": "ดูไฟล์ข้อมูล",
    "Backing up devices...": "กำลังสำรองข้อมูลอุปกรณ์...",
    "Backup Now": "เริ่มการสำรองข้อมูลทันที",
    "Running Configuration Backup...": "ระบบกำลังเริ่มการสำรองข้อมูลอุปกรณ์...",
    "Initializing connections...": "กำลังสร้างเซสชันการเชื่อมต่ออุปกรณ์...",
    "Backup Sessions History": "ประวัติไฟล์คอนฟิกที่สำรองย้อนหลัง",
    "Session / Timestamp": "วันเวลาของเซสชันที่สำรอง",
    "Devices Saved": "จำนวนอุปกรณ์ที่สำรองสำเร็จ",
    "View Session": "ดูไฟล์คอนฟิกของเซสชัน",
    "Backup Session Details": "รายการรายละเอียดไฟล์คอนฟิกและตารางเส้นทาง",
    "Close Details": "ปิดส่วนรายละเอียด",
    "File Type": "ประเภทข้อมูลไฟล์",
    "Filename": "ชื่อไฟล์เอกสาร",
    "View": "ดูรายละเอียดไฟล์",
    "Compare (Diff)": "เปรียบเทียบความต่าง (Diff)",
    "Running Config": "คอนฟิกการรัน (Running-Config)",
    "Routing Table": "ตารางจัดเส้นทาง (Routing Table)",
    "View Config": "การเปิดอ่านไฟล์คอนฟิก",
    "Git-style Config Diff Comparison": "เครื่องมือตรวจสอบความต่างของไฟล์คอนฟิก (Diff)",
    "Comparing files...": "กำลังประมวลผลเปรียบเทียบไฟล์ข้อมูล...",
    "No changes detected. The configurations are identical.": "ไม่พบการเปลี่ยนแปลงใดๆ ไฟล์ข้อมูลคอนฟิกมีความสอดคล้องตรงกันทุกบรรทัด",
    "No other historical backup sessions containing": "ไม่พบประวัติไฟล์สำรองอื่นๆ ของอุปกรณ์",
    "to compare with!": "เพื่อเปรียบเทียบ!",
    "Select a version of": "เลือกรอบการสำรองข้อมูลของ",
    "config to compare with": "เพื่อใช้เปรียบเทียบความต่างกับ",
    "Select Backup Version": "เลือกรอบไฟล์สำรองที่ต้องการใช้",
    "You must select a backup version!": "คุณต้องเลือกรอบไฟล์สำรองอย่างน้อยหนึ่งรอบ!",
    "Backup session initiated": "ระบบได้ส่งคำสั่งสำรองข้อมูลเข้าระบบหลักแล้ว",
    "Configuration backup successfully completed!": "ระบบได้ดำเนินการสำรองข้อมูลเสร็จสิ้นเรียบร้อยแล้ว!",
    "Backup failed. Check connection parameters.": "เกิดข้อผิดพลาดในการสำรองข้อมูล โปรดตรวจสอบค่าพารามิเตอร์การเชื่อมต่อ",

    // Settings Page
    "General": "ทั่วไป",
    "AI Model": "ระบบสมองกล AI",
    "Devices": "อุปกรณ์เครือข่าย",
    "Environment": "ระบบสภาพแวดล้อม (.env)",
    "Users": "ผู้ใช้งานระบบ",
    "Collector & Data": "ข้อมูลและการเก็บค่าพารามิเตอร์",
    "INTERVAL (SECONDS)": "รอบเวลาสแกนข้อมูล (วินาที)",
    "RETENTION (DAYS)": "ระยะเวลาเก็บรักษาข้อมูลเก่า (วัน)",
    "Interval (seconds)": "รอบเวลาสแกนข้อมูล (วินาที)",
    "Retention (days)": "ระยะเวลาการจัดเก็บข้อมูล (วัน)",
    "AI Model Thresholds": "ขีดจำกัดตรรกะระบบ AI",
    "LOAD (0-255)": "ปริมาณทราฟฟิกสูงสุด (0-255)",
    "RELIABILITY (0-255)": "ความเสถียรขั้นต่ำ (0-255)",
    "Load (0-255)": "ปริมาณทราฟฟิกสูงสุด (0-255)",
    "Reliability (0-255)": "ความเสถียรขั้นต่ำ (0-255)",
    "Link Type Rules": "กฎการแยกประเภทลิงก์เครือข่าย",
    "Define link categories such as Core, LAN, or Management by matching interface IP address prefixes.": "กำหนดประเภทเส้นลิงก์ (เช่น Core, LAN, Management) ตามช่วง IP Address ของอินเทอร์เฟส",
    "Subnet Prefix (e.g. 10.10.)": "หมายเลขซับเน็ตเริ่มต้น (เช่น 10.10.)",
    "Subnet Prefix (เช่น 10.10.)": "หมายเลขซับเน็ตเริ่มต้น (เช่น 10.10.)",
    "Link Type (e.g. Core)": "ประเภทการเชื่อมโยง (เช่น Core)",
    "Link Type (เช่น Core)": "ประเภทการเชื่อมโยง (เช่น Core)",
    "Action": "ตัวดำเนินการ",
    "Add Rule": "เพิ่มกฎการแยกประเภท",
    "Default Link Type": "ประเภทการเชื่อมโยงเริ่มต้น",
    "Ignored Interfaces (Skip Types)": "อินเทอร์เฟซที่ระบบละเว้น (Skip Types)",
    "Interfaces with these name prefixes are excluded from anomaly detection and charts, for example Loopback or Vlan.": "ระบบจะไม่นำอินเทอร์เฟสที่มีชื่อขึ้นต้นด้วยคำเหล่านี้ไปตรวจสอบ Anomaly หรือวาดกราฟ (เช่น Loopback, Vlan)",
    "Add Prefix": "เพิ่ม Prefix",
    "Save General Settings": "บันทึกข้อมูลทั่วไปทั้งหมด",
    "Retrain Workflow": "ระบบเทรนข้อมูลแบบจำลอง AI",
    "Model Version": "รุ่นเวอร์ชันของแบบจำลอง AI",
    "Model Status": "สถานะความพร้อมแบบจำลอง AI",
    "Training Rows": "จำนวนชุดข้อมูลสถิติที่ป้อนเรียนรู้",
    "Features": "มิติคุณสมบัติข้อมูลนำเข้า (Features)",
    "Precision": "ความแม่นยำรวมของ AI (Precision)",
    "Recall": "ความครอบคลุมการตรวจสอบ (Recall)",
    "False Positive Rate": "อัตราเตือนหลอกผิดพลาด (FPR)",
    "Supported Vendors": "แบรนด์อุปกรณ์ที่รองรับในขณะนี้",
    "Retrain Model": "เริ่มเทรนแบบจำลอง AI ทันที",
    "Retrain Log": "บันทึกรายงานขั้นตอนการเทรน AI",
    "No retrain has run in this dashboard session.": "ยังไม่มีการรันระบบเทรนแบบจำลอง AI ในเซสชันนี้",
    "Network Devices": "รายการพารามิเตอร์ของอุปกรณ์ทั้งหมด",
    "Add Device": "เพิ่มอุปกรณ์เครือข่าย",
    "Name": "ชื่ออุปกรณ์",
    "Host/IP": "หมายเลขไอพีแอดเดรส",
    "Type": "ระบบปฏิบัติการอุปกรณ์",
    "Save": "บันทึกการตั้งค่า",
    "Cancel": "ยกเลิก",
    "Delete": "ลบ",
    "Edit": "แก้ไข",
    "Update": "อัพเดท",
    "Environment Variables (.env)": "ตัวแปรสภาพแวดล้อม (.env)",
    "Secret values are never shown after save. Leave a secret field empty to keep the current value. Restart the app after changes.": "ค่าลับจะไม่แสดงหลังบันทึก หากไม่ต้องการเปลี่ยนค่าให้ปล่อยช่องลับว่างไว้ และรีสตาร์ตแอปหลังแก้ไข",
    "Discord Bot Token": "โทเคนบอต Discord",
    "Discord Channel ID": "รหัสช่อง Discord",
    "Device Username": "ชื่อผู้ใช้อุปกรณ์",
    "Device Password": "รหัสผ่านอุปกรณ์",
    "Enable Secret": "รหัส Enable Secret",
    "SNMP Community": "SNMP Community",
    "SNMPv3 Username": "ชื่อผู้ใช้ SNMPv3",
    "SNMPv3 Auth Password": "รหัสผ่าน Auth ของ SNMPv3",
    "SNMPv3 Privacy Password": "รหัสผ่าน Privacy ของ SNMPv3",
    "Save Environment": "บันทึก Environment",

    // Auth
    "Confirm Logout": "ยืนยันการออกจากระบบ",
    "Are you sure you want to log out of NetSentinel AI?": "คุณยืนยันที่จะออกจากระบบ NetSentinel AI หรือไม่?",
    "Cancel": "ยกเลิก",

    // Info Tooltips & Helper Text
    "Loading...": "กำลังโหลด...",
    "Error": "เกิดข้อผิดพลาด",
    "Success": "สำเร็จ",
    "Warning": "คำเตือน",
    "Info": "ข้อมูล",
    
    // Settings Placeholders & Helper Text
    "60": "60",
    "30": "30",
    "20": "20",
    "200": "200",
    "10": "10",
    "e.g. 192.168.1.": "เช่น 192.168.1.",
    "e.g. LAN": "เช่น LAN",
    "Other": "อื่นๆ",
    "e.g. Loopback": "เช่น Loopback",
    "e.g. R1, SW-Core": "เช่น R1, SW-Core",
    "e.g. 10.10.10.1": "เช่น 10.10.10.1",
    "e.g. Core, A, DMZ": "เช่น Core, A, DMZ",
    "public": "public",
    "Leave blank to keep current": "ปล่อยว่างไว้เพื่อเก็บค่าปัจจุบัน",
    "(saved — enter new to replace)": "(บันทึกแล้ว - ใส่ค่าใหม่เพื่อแทนที่)",
    "(not set)": "(ยังไม่ได้ตั้งค่า)",
    "min 6 characters": "อย่างน้อย 6 ตัวอักษร",
    "username": "ชื่อผู้ใช้",

    // Settings info tips
    "How often the collector polls network devices. Lower values make monitoring closer to real time.": "ช่วงเวลาในการดึงข้อมูลจากอุปกรณ์เครือข่ายทุกๆ X วินาที ยิ่งค่าน้อยจะยิ่งตรวจสอบได้แบบเรียลไทม์มากขึ้น",
    "How many days metric history is kept before old records are cleaned up to save storage.": "ระยะเวลาจัดเก็บข้อมูลสถิติในระบบคลังข้อมูล หลังจากพ้นจำนวนวันที่ระบุ ข้อมูลเก่าจะถูกเคลียร์เพื่อประหยัดพื้นที่",
    "Maximum traffic load threshold from 0-255. Ports above this value are more likely to be flagged as anomalous.": "เกณฑ์ทราฟฟิกสูงสุด (0-255) หากพอร์ตใดมีอัตราส่ง/รับข้อมูลสูงกว่าค่านี้ AI จะประเมินว่ามีโอกาสเป็นความผิดปกติ",
    "Minimum link reliability threshold from 0-255. 255 means fully reliable; values below the threshold are treated as risky.": "เกณฑ์ความเสถียรของลิงก์ (0-255) ค่า 255 คือเสถียร 100% หากค่าตกลงมาต่ำกว่าที่ระบุ AI จะถือว่าสายส่งมีปัญหา",
    "Packet error threshold such as CRC or input errors. Values above this per collection cycle trigger an alert.": "เกณฑ์จำนวนแพ็กเก็ตที่เสียหาย (เช่น CRC, Input Errors) หากพบค่าเสียหายต่อรอบสูงกว่านี้ จะเตือนภัยทันที",
    "Fallback link category used when an interface IP does not match any subnet rule above.": "ประเภทของลิงก์เริ่มต้น หาก IP ของอินเทอร์เฟสไม่เข้าเกณฑ์กฎ Subnet ด้านบน",
    "Current AI model version. Retraining increases the model version.": "เวอร์ชันโมเดล AI ปัจจุบันที่กำลังใช้งาน ยิ่งเทรนซ้ำเวอร์ชันจะยิ่งเพิ่มขึ้น",
    "Current AI model state, such as ready when it can collect and predict data.": "สถานะของโมเดล AI ในปัจจุบัน (เช่น ready คือพร้อมใช้งานสำหรับการดึงและทำนายข้อมูล)",
    "Number of historical metric rows used to train the AI model.": "จำนวนแถวของข้อมูลสถิติประวัติทราฟฟิกในอดีตที่นำมาใช้ป้อนให้ AI เรียนรู้พฤติกรรม",
    "Number of network data features used by AI, such as load, reliability, and input errors.": "จำนวนตัวแปร/มิติข้อมูลเครือข่ายที่นำไปให้ AI ตรวจสอบ (เช่น load, reliability, input errors)",
    "AI alert precision. Higher means alerts are more likely to represent real issues and fewer false alarms.": "ความแม่นยำในการเตือนภัยของ AI ยิ่งสูงแปลว่าเมื่อมีการเตือนจะเป็นภัยคุกคามจริงไม่ค่อยส่งการเตือนหลอก (False Alarm)",
    "Detection recall. Higher means AI catches more of the real anomalies without missing them.": "อัตราการตรวจจับความผิดปกติที่มีอยู่ทั้งหมด ยิ่งสูงแปลว่า AI สามารถจับความผิดปกติได้ครบถ้วนไม่ตกหล่น",
    "False positive rate. Lower is better and means normal traffic is less likely to trigger noisy alerts.": "อัตราการแจ้งเตือนผิดพลาด (False Positive) ยิ่งน้อยยิ่งดี บ่งบอกว่า AI จะไม่แจ้งเตือนรบกวนทราฟฟิกปกติ",
    "Network vendors currently supported by NetSentinel AI commands and CLI structures.": "ยี่ห้อของอุปกรณ์เครือข่ายที่ระบบ NetSentinel AI สนับสนุนคำสั่งและโครงสร้าง CLI ในขณะนี้",
    "Device display name, for example R1 or SW-Core. It should match the device hostname.": "ชื่อเรียกอุปกรณ์ในระบบ เช่น R1, SW-Core (ควรตรงกับ Hostname ของตัวอุปกรณ์)",
    "Management IP address used for SNMP or terminal CLI access.": "IP Address สำหรับใช้จัดการเชื่อมต่อผ่าน SNMP หรือ Terminal CLI",
    "Device operating system used to select the right CLI, SSH, or Telnet workflow for bounce and rate-limit actions.": "ระบบปฏิบัติการของอุปกรณ์เพื่อจับคู่โปรโตคอล CLI/SSH/Telnet ในการสั่ง Bounce หรือ Rate limit",
    "Network layer or device role used for classification and severity analysis.": "ระดับชั้นโครงสร้างของอุปกรณ์ในเครือข่าย ช่วยเรื่องจัดประเภทและวิเคราะห์ระดับความรุนแรงของภัย",
    "Logical group or physical location of the device, such as Core, A, or Zone-DMZ.": "การจัดกลุ่มทางตรรกะ หรือที่ตั้งทางกายภาพของอุปกรณ์ เช่น Core, A, Zone-DMZ",
    "SNMP read-only community string. The default is public.": "รหัสผ่าน Community String สำหรับเข้าถึงบริการ SNMP Read-Only (ค่าเริ่มต้นคือ public)",
    "Discord bot token used to send alerts. The saved value is hidden; enter a new value only when replacing it.": "โทเคนของบอต Discord สำหรับส่งแจ้งเตือน ระบบจะซ่อนค่าที่บันทึกไว้ ใส่ค่าใหม่เฉพาะเมื่อต้องการแทนที่",
    "Discord channel ID where NetSentinel sends notifications and alerts.": "รหัสช่อง Discord ที่ NetSentinel ใช้ส่งข้อความแจ้งเตือน",
    "Default username used when connecting to network devices by SSH or Telnet.": "ชื่อผู้ใช้เริ่มต้นสำหรับเชื่อมต่ออุปกรณ์เครือข่ายผ่าน SSH หรือ Telnet",
    "Default login password for network device access. Leave blank to keep the saved password.": "รหัสผ่านเริ่มต้นสำหรับเข้าอุปกรณ์เครือข่าย ปล่อยว่างไว้เพื่อเก็บค่าที่บันทึกไว้",
    "Privilege mode secret used for enable mode on Cisco-style devices.": "รหัสสำหรับเข้าโหมด privilege หรือ enable บนอุปกรณ์แบบ Cisco",
    "SNMP v1/v2c read community used by the collector when polling device metrics.": "ค่า SNMP v1/v2c read community ที่ collector ใช้ดึงข้อมูลสถิติจากอุปกรณ์",
    "SNMPv3 security username. Leave empty if your devices use SNMP v1/v2c only.": "ชื่อผู้ใช้ความปลอดภัยของ SNMPv3 ปล่อยว่างได้หากใช้งานเฉพาะ SNMP v1/v2c",
    "SNMPv3 authentication password used to verify collector access.": "รหัสผ่าน authentication ของ SNMPv3 สำหรับยืนยันสิทธิ์ collector",
    "SNMPv3 privacy password used for encrypted SNMP polling.": "รหัสผ่าน privacy ของ SNMPv3 สำหรับการดึงข้อมูล SNMP แบบเข้ารหัส",
  },

  /**
   * Get translation for a text
   */
  translate: function(text) {
    if (!text) return text;

    // If current language is English
    if (this.currentLang === 'en') {
      // If text is already English, return it
      // If text is Thai (exists as a value), find its English key
      for (const key in this.dictionary) {
        if (this.dictionary[key] === text) return key;
      }
      return text;
    }

    // Current language is Thai: translate English keys to Thai
    if (this.dictionary[text]) return this.dictionary[text];

    // If text is already Thai but no direct key, return as-is
    return text;
  },


  /**
   * Translate entire page - comprehensive approach
   */
  translatePage: function() {
    // 1. Translate ALL text nodes recursively
    this._walkAndTranslateNodes(document.body);

    // 2. Translate placeholders
    document.querySelectorAll('input[placeholder], textarea[placeholder]').forEach(el => {
      el.setAttribute('placeholder', this.translate(el.getAttribute('placeholder')));
    });

    // 3. Translate titles, aria-labels, sidebar tooltips, and info tooltips
    document.querySelectorAll('[title], [aria-label], [data-tooltip], [data-tip]').forEach(el => {
      if (el.hasAttribute('title')) {
        el.setAttribute('title', this.translate(el.getAttribute('title')));
      }
      if (el.hasAttribute('aria-label')) {
        el.setAttribute('aria-label', this.translate(el.getAttribute('aria-label')));
      }
      if (el.hasAttribute('data-tooltip')) {
        el.setAttribute('data-tooltip', this.translate(el.getAttribute('data-tooltip')));
      }
      if (el.hasAttribute('data-tip')) {
        el.setAttribute('data-tip', this.translate(el.getAttribute('data-tip')));
      }
    });

    // 4. Update language button
    const langBtn = document.getElementById('lang-toggle-text');
    if (langBtn) {
      langBtn.textContent = this.currentLang === 'en' ? 'English / ไทย' : 'ภาษาไทย / EN';
    }

    // 5. Update html lang attribute
    document.documentElement.lang = this.currentLang;

    // 6. Dispatch only when the language actually changes. MutationObserver
    // translations also call translatePage(), and repeatedly firing this event
    // can make dynamic pages fetch and redraw in a loop.
    if (this.lastDispatchedLang !== this.currentLang) {
      this.lastDispatchedLang = this.currentLang;
      document.dispatchEvent(new CustomEvent('languagechanged', { 
        detail: { lang: this.currentLang } 
      }));
    }
  },

  /**
   * Recursively walk and translate all text nodes
   */
  _walkAndTranslateNodes: function(element) {
    const children = Array.from(element.childNodes);
    
    children.forEach(node => {
      // Skip certain elements
      if (node.nodeType === Node.ELEMENT_NODE) {
        const el = node;
        if (el.closest('.remediation-progress-card') || 
            el.closest('.swal2-container') ||
            el.closest('script') ||
            el.closest('style')) {
          return;
        }

        // Recursively process children
        this._walkAndTranslateNodes(el);
      } else if (node.nodeType === Node.TEXT_NODE) {
        const text = node.nodeValue.trim();
        if (!text || text.length === 0) return;

        // Skip if parent is in excluded elements
        if (node.parentElement.closest('.remediation-progress-card') || 
            node.parentElement.closest('.swal2-container') ||
            node.parentElement.closest('script') ||
            node.parentElement.closest('style')) {
          return;
        }

        const translated = this.translate(text);
        if (translated !== text) {
          node.nodeValue = translated;
        }
      }
    });
  },

  /**
   * Toggle language without page refresh
   */
  toggleLanguage: function() {
    this.currentLang = this.currentLang === 'en' ? 'th' : 'en';
    localStorage.setItem('netsentinel_lang', this.currentLang);
    
    // Disconnect observer temporarily
    if (this.observer) {
      this.observer.disconnect();
    }
    
    // Translate page immediately
    this.translatePage();
    
    // Reload page content via AJAX if needed (refresh data without full reload)
    this._softReloadPageContent();
    
    // Reconnect observer
    this.setupObserver();
  },

  /**
   * Soft reload - refresh page content without full reload
   */
  _softReloadPageContent: function() {
    // Reload current page data via AJAX
    const currentPath = window.location.pathname;
    
    // Fetch fresh page content
    fetch(currentPath, {
      method: 'GET',
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
    .then(response => response.text())
    .then(html => {
      // Parse new HTML
      const parser = new DOMParser();
      const newDoc = parser.parseFromString(html, 'text/html');
      
      // Find main content area and update it
      const mainContent = document.querySelector('main') || document.querySelector('[role="main"]');
      const newContent = newDoc.querySelector('main') || newDoc.querySelector('[role="main"]');
      
      if (mainContent && newContent) {
        mainContent.innerHTML = newContent.innerHTML;
        
        // Re-translate the new content
        this.translatePage();
      }
    })
    .catch(err => {
      // If soft reload fails, do full reload
      console.warn('Soft reload failed, doing full reload:', err);
      location.reload();
    });
  },

  /**
   * Setup MutationObserver to auto-translate dynamically added content
   */
  setupObserver: function() {
    if (this.observer) {
      this.observer.disconnect();
    }

    this.observer = new MutationObserver((mutations) => {
      // Debounce to avoid excessive translations
      clearTimeout(this.observerTimeout);
      this.observerTimeout = setTimeout(() => {
        this.translatePage();
      }, 100);
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: false,
      attributes: false
    });
  },

  /**
   * Translate API response data
   * Deep translates all string values in an object/array
   */
  translateData: function(data) {
    if (this.currentLang === 'en') return data;

    if (typeof data === 'string') {
      return this.translate(data);
    } else if (Array.isArray(data)) {
      return data.map(item => this.translateData(item));
    } else if (typeof data === 'object' && data !== null) {
      const translated = {};
      for (const key in data) {
        if (data.hasOwnProperty(key)) {
          translated[key] = this.translateData(data[key]);
        }
      }
      return translated;
    }
    return data;
  },

  /**
   * Initialize i18n
   */
  init: function() {
    this.currentLang = localStorage.getItem('netsentinel_lang') || 'en';
    
    // Translate on load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        this.translatePage();
        this.setupObserver();
      });
    } else {
      this.translatePage();
      this.setupObserver();
    }

    // Expose global function
    window.toggleLanguage = () => this.toggleLanguage();
  }
};

// Auto-initialize when script loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => NetSentinelI18n.init());
} else {
  NetSentinelI18n.init();
}

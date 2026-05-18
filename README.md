# NetSentinel AI

ระบบตรวจจับความผิดปกติบนเครือข่าย Cisco แบบ Real-time

ดึงข้อมูลจาก Router ผ่าน SNMP → วิเคราะห์ด้วย Rule-based + Isolation Forest → แจ้งเตือนผ่าน Discord Bot → สั่งแก้ไขจากปุ่มกดได้เลย พร้อม Dashboard แสดงสถานะ

---

## Screenshots

### Dashboard — สถานะปกติ
<!-- ![Dashboard Normal](screenshots/dashboard_normal.png) -->

### Dashboard — ตอนมี Anomaly
<!-- ![Dashboard Anomaly](screenshots/dashboard_anomaly.png) -->

### Discord — แจ้งเตือน Anomaly พร้อมปุ่มกด
<!-- ![Discord Alert](screenshots/discord_alert.png) -->

### Discord — สั่ง Fix สำเร็จ
<!-- ![Discord Fix](screenshots/discord_fix.png) -->

### Discord — คำสั่ง !analytics
<!-- ![Discord Analytics](screenshots/discord_analytics.png) -->

### Terminal — Log ตอนรันปกติ
<!-- ![Terminal Normal](screenshots/terminal_normal.png) -->

### Terminal — Log ตอนพบ Anomaly
<!-- ![Terminal Anomaly](screenshots/terminal_anomaly.png) -->

### GNS3 — Topology ที่ใช้ทดสอบ
<!-- ![GNS3 Topology](screenshots/gns3_topology.png) -->

---

## สิ่งที่ระบบทำได้

- เก็บข้อมูล interface (status, reliability, TX/RX load, errors) จาก Router ผ่าน SNMP ทุก 60 วินาที
- วิเคราะห์ด้วย 2 ระบบคู่ขนาน: Rule-based threshold + Isolation Forest AI
- แจ้งเตือน anomaly ผ่าน Discord พร้อมปุ่มกดสั่ง fix, rate limit, check status
- Dashboard เว็บแสดงสถานะ interface, กราฟ traffic, ประวัติ anomaly
- เทรน AI ใหม่อัตโนมัติทุก 24 ชั่วโมง
- รองรับ SNMPv2c และ SNMPv3 (SHA/AES)
- ปุ่มกดใน Discord จำกัดเฉพาะ Admin เท่านั้น

---

## โครงสร้างโปรเจค

```
├── main.py                  # จุดเริ่มต้น รันทุก thread
├── train_model.py           # เทรน AI Model
├── requirements.txt
├── .env                     # ค่าลับ (ไม่ขึ้น git)
│
├── app/
│   ├── collector.py         # ดึงข้อมูลจาก Router ผ่าน SNMP
│   ├── snmp_helper.py       # SNMP v2c/v3 + กรองค่าขยะ GNS3
│   ├── predictor.py         # Rules + AI วิเคราะห์คู่ขนาน
│   ├── bot.py               # Discord Bot
│   ├── db.py                # MySQL (SQLAlchemy)
│   └── runtime.py           # Shutdown flag
│
├── web/
│   ├── dashboard.py         # Flask + SocketIO
│   └── templates/
│       └── dashboard.html
│
├── config/
│   ├── config.yaml          # Threshold, interval (ไม่ขึ้น git)
│   └── devices.yaml         # รายการ Router (ไม่ขึ้น git)
│
└── models/
    └── anomaly_model_v2.pkl # AI Model (ไม่ขึ้น git)
```

---

## ต้องมีอะไรบ้าง

- Python 3.10+
- MySQL 8.0+
- GNS3 พร้อม Cisco IOS image
- Discord Bot Token (สร้างจาก https://discord.com/developers/applications)

---

## วิธีติดตั้ง

```bash
git clone https://github.com/YOUR_USERNAME/network-ai-v2-web.git
cd network-ai-v2-web
pip install -r requirements.txt
```

สร้าง Database:

```sql
CREATE DATABASE network_ai_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Copy ไฟล์ config แล้วแก้ค่า:

```bash
cp .env.example .env
cp config/config.example.yaml config/config.yaml
cp config/devices.example.yaml config/devices.yaml
```

---

## Configuration

### `.env`

```env
DB_URL=mysql+mysqlconnector://root:รหัสผ่าน@localhost/network_ai_v2

DISCORD_TOKEN=token_ของบอท
DISCORD_CHANNEL_ID=channel_id

DEVICE_USERNAME=admin
DEVICE_PASSWORD=admin123
DEVICE_SECRET=admin123

SNMP_COMMUNITY=public

# SNMPv3 (ถ้าไม่ใส่จะใช้ v2c)
# SNMP_V3_USER=netsentinel
# SNMP_V3_AUTH=admin12345
# SNMP_V3_PRIV=admin12345
```

### `config/devices.yaml`

ใส่ Router ที่จะมอนิเตอร์ เพิ่มกี่ตัวก็ได้:

```yaml
devices:
  - name: R1
    host: 10.10.100.1
    device_type: cisco_ios_telnet
    location: Core
    zone: A

  - name: R2
    host: 192.168.189.10
    device_type: cisco_ios_telnet
    location: Core
    zone: Core
```

### `config/config.yaml`

ปรับ threshold ตามต้องการ:

```yaml
model:
  threshold_load: 20          # rxload/txload > 20 = anomaly (0-255)
  threshold_reliability: 200  # reliability < 200 = anomaly
  threshold_errors: 10        # input errors > 10 = anomaly
  retrain_interval_hours: 24

collector:
  interval: 60                # เก็บข้อมูลทุก 60 วินาที
```

---

## Config Router ใน GNS3

ทุกตัวต้อง config SNMP:

```
conf t
snmp-server community public ro
exit
wr
```

ถ้าจะใช้ SNMPv3:

```
conf t
no snmp-server community public ro
snmp-server group V3Group v3 priv read v3view
snmp-server view v3view iso included
snmp-server user netsentinel V3Group v3 auth sha admin12345 priv aes 128 admin12345
exit
wr
```

ถ้าจะใช้ปุ่ม Fix/Rate Limit ต้อง config Telnet ด้วย:

```
conf t
enable secret admin123
username admin privilege 15 secret admin123
line vty 0 4
 login local
 transport input telnet
exit
wr
```

---

## วิธีใช้

```bash
# รันระบบ (ตาราง DB สร้างอัตโนมัติ)
python main.py

# รอเก็บข้อมูลสัก 10 นาที แล้วเทรน AI
python train_model.py

# รีสตาร์ทเพื่อโหลด model ใหม่
python main.py
```

- Dashboard: http://localhost:5000
- หลังจากนี้ AI จะเทรนใหม่เองทุก 24 ชั่วโมง

### เปลี่ยน Topology

แก้ `config/devices.yaml` → config SNMP บน Router ใหม่ → รัน `python main.py` → รอสักพักแล้ว `python train_model.py`

---

## Discord Bot Commands

| คำสั่ง | ทำอะไร |
|--------|--------|
| `!status` | ดูสถานะ interface ทั้งหมด |
| `!history` | ดู anomaly 10 รายการล่าสุด |
| `!analytics` | สรุป anomaly, uptime, traffic |
| `!help` | ดูคำสั่งทั้งหมด |

ปุ่มกดบน alert (เฉพาะ Admin): Approve Fix, Rate Limit, Remove Limit, Check Status, Ignore

---

## AI Model

ใช้ **Isolation Forest** เรียนรู้จากข้อมูลปกติ แล้วจับ pattern ที่ผิดแปลกออกมา

ทำงานคู่ขนานกับ Rules ทุกรอบ:
- `rules+ai` — ทั้งสองเห็นตรงกัน
- `rules` — เฉพาะ rules เจอ
- `ai` — เฉพาะ AI เจอ (pattern แปลกที่ rules ไม่มีกฎครอบคลุม)
- `healthy` — ผ่านทั้งคู่

---

## API

| Method | Endpoint | คำอธิบาย |
|--------|----------|---------|
| GET | `/api/status` | สถานะ interface ล่าสุด |
| GET | `/api/anomalies` | ประวัติ anomaly |
| GET | `/api/analytics` | สรุปสถิติ |
| GET | `/api/traffic` | Traffic trend 1 ชั่วโมง |
| POST | `/api/fix/<device>/<intf>` | สั่ง no shutdown |
| POST | `/api/ratelimit/<device>/<intf>` | ใส่ rate limit |
| POST | `/api/removelimit/<device>/<intf>` | ถอด rate limit |

---

## License

This project is for educational purposes.

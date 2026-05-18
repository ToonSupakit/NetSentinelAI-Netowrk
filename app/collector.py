# นำเข้าไลบรารีที่จำเป็นสำหรับการเก็บข้อมูลจากอุปกรณ์เครือข่าย
from netmiko import ConnectHandler  # ไลบรารีสำหรับเชื่อมต่อกับอุปกรณ์เครือข่าย
from app.db import save_log  # ฟังก์ชันสำหรับบันทึกข้อมูลลงฐานข้อมูล
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml  # สำหรับอ่านไฟล์การตั้งค่า
import re  # สำหรับการประมวลผลข้อความด้วย regular expression
import time  # สำหรับจัดการเวลา
import os
import logging
from dotenv import load_dotenv
from app.snmp_helper import get_snmp_interfaces

load_dotenv()
log = logging.getLogger(__name__)

# อ่านไฟล์การตั้งค่าจาก config.yaml
with open('config/config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# อ่านไฟล์ข้อมูลอุปกรณ์จาก devices.yaml
with open('config/devices.yaml', 'r', encoding='utf-8') as f:
    devices_config = yaml.safe_load(f)

# ดึงค่าการตั้งค่าจากไฟล์ config
SKIP_TYPES            = [s for s in config['anomaly']['skip_types'] if s is not None]  # ประเภท interface ที่จะข้าม
THRESHOLD_LOAD        = config['model']['threshold_load']  # ค่า threshold สำหรับ network load
THRESHOLD_RELIABILITY = config['model']['threshold_reliability']  # ค่า threshold สำหรับ reliability
THRESHOLD_ERRORS      = config['model']['threshold_errors']  # ค่า threshold สำหรับ input errors
MAX_RETRIES           = 3  # จำนวนครั้งสูงสุดในการ retry
RETRY_DELAY           = 5  # ระยะเวลาหน่วงระหว่าง retry (วินาที)

# ── Link Type — อ่านจาก config (ไม่ hardcode IP) ──────────────────────────
LINK_TYPE_RULES   = config.get('link_types', {}).get('rules', [])
LINK_TYPE_DEFAULT = config.get('link_types', {}).get('default', 'Other')

# ── Device Credentials — ค่า default จาก .env ─────────────────────────────
DEFAULT_USERNAME = os.getenv('DEVICE_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('DEVICE_PASSWORD', 'admin')
DEFAULT_SECRET   = os.getenv('DEVICE_SECRET', 'admin')


# ── ฟังก์ชันสำหรับกรอง interface ที่ไม่ต้องการตรวจสอบ ─────────────────────────
def should_skip(intf, ip, is_admin_down):
    """ตรวจสอบว่าควรข้าม interface นี้หรือไม่"""
    # ตรวจสอบว่าเป็นประเภทที่ต้องข้ามหรือไม่
    for skip in SKIP_TYPES:
        if intf.startswith(skip):
            return True
    # ข้ามถ้าไม่มี IP — พอร์ตที่ไม่มี IP ถือว่าไม่ได้ใช้งาน ไม่ต้องมอนิเตอร์
    if ip == 'unassigned':
        return True
    return False

# ── ฟังก์ชันสำหรับกำหนดประเภทการเชื่อมต่อจาก IP (อ่านจาก config) ────────────
def get_link_type(ip):
    """กำหนดประเภทของการเชื่อมต่อจาก config.yaml link_types rules"""
    if ip == 'unknown':
        return 'Unknown'
    for rule in LINK_TYPE_RULES:
        if ip.startswith(rule['prefix']) or rule['prefix'] in ip:
            return rule['type']
    return LINK_TYPE_DEFAULT

# ── ฟังก์ชันสำหรับแปลงข้อมูลจากคำสั่ง show interfaces ─────────────────────────────────
def parse_interfaces(raw):
    """แปลงข้อมูลจากคำสั่ง show interfaces เป็นโครงสร้างข้อมูลที่ใช้งานได้"""
    result  = {}
    current = None
    for line in raw.splitlines():
        # หาบรรทัดที่มีข้อมูลสถานะของ interface
        m = re.match(r'^(\S+)\s+is\s+(.+),\s+line protocol is\s+(\S+)', line)
        if m:
            current = m.group(1)
            result[current] = {
                'phys'        : m.group(2).strip(),  # สถานะ physical
                'proto'       : m.group(3).strip(),  # สถานะ protocol
                'reliability' : '255',  # ค่าความเสถียร (default)
                'txload'      : '1',    # ค่า load ขาออก (default)
                'rxload'      : '1',    # ค่า load ขาเข้า (default)
                'input_errors': '0'     # จำนวน input errors (default)
            }
        if current:
            # หาค่า reliability, txload, rxload
            r = re.search(r'reliability (\d+)/255,\s*txload (\d+)/255,\s*rxload (\d+)/255', line)
            if r:
                result[current]['reliability'] = r.group(1)
                result[current]['txload']      = r.group(2)
                result[current]['rxload']      = r.group(3)
            # หาจำนวน input errors
            e = re.search(r'(\d+) input errors', line)
            if e:
                result[current]['input_errors'] = e.group(1)
    return result

# ── ฟังก์ชันสำหรับกำหนด label (ปกติ/ผิดปกติ) ───────────────────────────────────
def get_label(status_num, protocol_num, network_load,
              rxload, reliability, input_errors, is_admin_down):
    """กำหนด label ว่า interface เป็นปกติหรือผิดปกติจากพารามิเตอร์ต่างๆ"""
    # ตรวจสอบสถานะต่างๆ ว่าเป็นความผิดปกติหรือไม่
    if is_admin_down:                        return 'anomaly'  # ถูกปิดด้วยคำสั่ง shutdown
    if status_num   == 0:                    return 'anomaly'  # physical down
    if protocol_num == 0:                    return 'anomaly'  # protocol down
    if network_load > THRESHOLD_LOAD:        return 'anomaly'  # traffic ขาออกสูง
    if rxload       > THRESHOLD_LOAD:        return 'anomaly'  # traffic ขาเข้าสูง
    if reliability  < THRESHOLD_RELIABILITY: return 'anomaly'  # ความเสถียรต่ำ
    if input_errors > THRESHOLD_ERRORS:      return 'anomaly'  # input errors สูง
    return 'normal'  # ถ้าผ่านการตรวจสอบทั้งหมด ถือว่าปกติ

# ── ดึง credentials ของ device (ใช้ default จาก .env ถ้าไม่ระบุ) ─────────────
def get_device_credentials(device):
    """ดึง credentials จาก device config หรือ .env default"""
    return {
        'device_type': device['device_type'],
        'host'       : device['host'],
        'username'   : device.get('username') or DEFAULT_USERNAME,
        'password'   : device.get('password') or DEFAULT_PASSWORD,
        'secret'     : device.get('secret') or DEFAULT_SECRET,
    }

def collect_device(device, on_timeout=None):
    """เก็บข้อมูล interface ทั้งหมดจากอุปกรณ์เดียวผ่าน SNMP"""
    host = device['host']
    community = device.get('snmp_community', os.getenv('SNMP_COMMUNITY', 'public'))
    
    for attempt in range(MAX_RETRIES):
        try:
            results = []
            
            # ดึงข้อมูลผ่าน SNMP
            interfaces_data = get_snmp_interfaces(host, community)
            
            for data in interfaces_data:
                intf = data['intf']
                ip = data['ip']
                is_admin_down = data.get('is_admin_down', False)
                
                if should_skip(intf, ip, is_admin_down):
                    continue

                status_num = 0 if (is_admin_down or data['status'] == 'down') else 1
                protocol_num = 1 if data['protocol'] == 'up' else 0
                
                reliability = int(data['reliability'])
                network_load = int(data['network_load'])
                rxload = int(data['rxload'])
                input_errors = int(data['input_errors'])
                link_type = get_link_type(ip)
                
                label = get_label(
                    status_num, protocol_num,
                    network_load, rxload,
                    reliability, input_errors,
                    is_admin_down
                )
                
                log_id = save_log(
                    device['name'], intf, ip,
                    data['status'], data['protocol'],
                    reliability, network_load, rxload, input_errors,
                    link_type,
                    device.get('zone', 'Unknown'),
                    device.get('location', 'Unknown'),
                    label
                )
                
                results.append({
                    'log_id'       : log_id,
                    'device'       : device['name'],
                    'intf'         : intf,
                    'ip'           : ip,
                    'status_num'   : status_num,
                    'protocol_num' : protocol_num,
                    'reliability'  : reliability,
                    'network_load' : network_load,
                    'rxload'       : rxload,
                    'input_errors' : input_errors,
                    'link_type'    : link_type,
                    'label'        : label,
                    'is_admin_down': is_admin_down
                })
                
            # เมื่อเก็บข้อมูลสำเร็จ → update record ALL ให้เป็น up (กรณีเคย down)
            save_log(
                device['name'], 'ALL', host,
                'up', 'up',
                255, 0, 0, 0,
                'Unknown',
                device.get('zone', 'Unknown'),
                device.get('location', 'Unknown'),
                'normal'
            )

            log.info(f"{device['name']}: เก็บได้ {len(results)} interface")
            return results

        except Exception as e:
            # จัดการการ retry ถ้าเชื่อมต่อล้มเหลว
            if attempt < MAX_RETRIES - 1:
                log.warning(f"{device['name']} retry {attempt+1}/{MAX_RETRIES}: {e}")
                time.sleep(RETRY_DELAY)
            else:
                log.error(f"{device['name']}: หมด retry แล้ว — {e}")
                # แจ้งเตือน timeout ถ้ามีฟังก์ชัน callback
                if on_timeout:
                    on_timeout({
                        'device': device['name'],
                        'host'  : device['host'],
                        'zone'  : device.get('zone', 'Unknown'),
                        'error' : str(e)
                    })

                # บันทึก device down ลง DB เพื่อให้ predictor ตรวจจับได้
                log_id = save_log(
                    device['name'], 'ALL', device['host'],
                    'down', 'down',
                    0, 0, 0, 0,
                    'Unknown',
                    device.get('zone', 'Unknown'),
                    device.get('location', 'Unknown'),
                    'anomaly'
                )
                return [{
                    'log_id'       : log_id,
                    'device'       : device['name'],
                    'intf'         : 'ALL',
                    'ip'           : device['host'],
                    'status_num'   : 0,
                    'protocol_num' : 0,
                    'reliability'  : 0,
                    'network_load' : 0,
                    'rxload'       : 0,
                    'input_errors' : 0,
                    'link_type'    : 'Unknown',
                    'label'        : 'anomaly',
                    'is_admin_down': False,
                    'is_device_down': True,
                    'error'        : str(e)
                }]

    return []

# ── ฟังก์ชันสำหรับเก็บข้อมูลจากอุปกรณ์ทั้งหมด (พร้อมกัน) ─────────────────
def collect_all(on_timeout=None):
    """เก็บข้อมูล interface ทั้งหมดจากอุปกรณ์ทุกตัว — ใช้ ThreadPoolExecutor"""
    all_results = []
    devices = devices_config['devices']
    max_workers = min(len(devices), 8)  # ไม่เกิน 8 threads

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(collect_device, device, on_timeout): device['name']
            for device in devices
        }
        for future in as_completed(futures):
            device_name = futures[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                log.error(f"{device_name}: ThreadPool error — {e}")

    return all_results
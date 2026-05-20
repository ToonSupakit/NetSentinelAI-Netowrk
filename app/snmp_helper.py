import asyncio
import logging
import os
import time
from pysnmp.hlapi.v3arch.asyncio import *

log = logging.getLogger(__name__)
_OCTET_CACHE = {}


DEFAULT_OIDS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "locIfInLoad": "1.3.6.1.4.1.9.2.2.1.1.93",
    "locIfOutLoad": "1.3.6.1.4.1.9.2.2.1.1.94",
    "locIfReliability": "1.3.6.1.4.1.9.2.2.1.1.95",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
}


def get_snmp_auth(community):
    """ส่งคืน Auth object สำหรับ SNMP (v2c หรือ v3)"""
    v3_user = os.getenv("SNMP_V3_USER")
    if v3_user:
        v3_auth = os.getenv("SNMP_V3_AUTH")
        v3_priv = os.getenv("SNMP_V3_PRIV")
        return UsmUserData(
            v3_user,
            authKey=v3_auth,
            privKey=v3_priv,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
    return CommunityData(community)


async def snmp_walk_async(host, community, oid_str):
    """Walk SNMP OID tree, return dict of {ifIndex: value}"""
    results = {}
    snmpEngine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        async for errorIndication, errorStatus, errorIndex, varBinds in walk_cmd(
            snmpEngine,
            get_snmp_auth(community),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid_str)),
            lexicographicMode=False,
        ):
            if errorIndication:
                raise Exception(str(errorIndication))
            if errorStatus:
                raise Exception(errorStatus.prettyPrint())

            for varBind in varBinds:
                idx = str(varBind[0][-1])
                try:
                    val = int(varBind[1])
                except:
                    val = str(varBind[1])
                results[idx] = val
    except Exception as e:
        log.warning(f"SNMP Walk error on {host} for {oid_str}: {e}")

    return results


async def snmp_walk_ip_map(host, community):
    """ดึง IP mapping: ifIndex -> IP address จาก ipAdEntIfIndex

    OID 1.3.6.1.2.1.4.20.1.2 มีโครงสร้าง:
      ipAdEntIfIndex.A.B.C.D = ifIndex
    โดย A.B.C.D คือ IP address ที่ฝังอยู่ใน OID เอง
    """
    ip_map = {}  # {ifIndex_str: ip_address}
    snmpEngine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        async for errorIndication, errorStatus, errorIndex, varBinds in walk_cmd(
            snmpEngine,
            get_snmp_auth(community),
            target,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.2")),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                oid = varBind[0]
                if_index = str(varBind[1])
                # ดึง IP จาก 4 ตัวท้ายของ OID
                # เช่น 1.3.6.1.2.1.4.20.1.2.10.10.1.1 -> IP = 10.10.1.1
                oid_str = str(oid)
                parts = oid_str.split(".")
                if len(parts) >= 4:
                    ip_addr = ".".join(parts[-4:])
                    ip_map[if_index] = ip_addr
    except Exception as e:
        log.warning(f"SNMP IP map error on {host}: {e}")
    return ip_map


def _valid_load(value):
    return isinstance(value, int) and 0 <= value <= 255


def _interface_speed_bps(data, idx):
    high_speed = data.get("ifHighSpeed", {}).get(idx)
    if isinstance(high_speed, int) and high_speed > 0:
        return high_speed * 1_000_000
    speed = data.get("ifSpeed", {}).get(idx)
    if isinstance(speed, int) and speed > 0:
        return speed
    return None


def _octet_load(host, idx, direction, current_value, speed_bps, now):
    if not isinstance(current_value, int) or current_value < 0 or not speed_bps:
        return 1
    key = (host, idx, direction)
    previous = _OCTET_CACHE.get(key)
    _OCTET_CACHE[key] = (now, current_value)
    if not previous:
        return 1
    prev_time, prev_value = previous
    elapsed = max(now - prev_time, 0.001)
    delta = current_value - prev_value
    if delta < 0:
        return 1
    bits_per_second = (delta * 8) / elapsed
    return max(0, min(255, int(round((bits_per_second / speed_bps) * 255))))


def get_snmp_interfaces(host, community, oid_overrides=None):
    """ดึงข้อมูล interface ทั้งหมดผ่าน SNMP — sync wrapper"""

    async def _gather():
        oids = dict(DEFAULT_OIDS)
        if isinstance(oid_overrides, dict):
            oids.update({k: v for k, v in oid_overrides.items() if isinstance(k, str) and isinstance(v, str)})

        tasks = {k: snmp_walk_async(host, community, v) for k, v in oids.items()}
        # เพิ่ม IP map task
        tasks["ip_map"] = snmp_walk_ip_map(host, community)

        results = await asyncio.gather(*tasks.values())
        return dict(zip(tasks.keys(), results))

    data = asyncio.run(_gather())

    # ip_map: {ifIndex -> IP}
    ip_map = data.get("ip_map", {})

    interfaces = []
    ifDescr = data.get("ifDescr", {})
    now = time.time()

    for idx, name in ifDescr.items():
        if not name or str(name).startswith("Null") or "Loopback" in str(name):
            continue

        status_val = data.get("ifOperStatus", {}).get(idx, 2)
        admin_val = data.get("ifAdminStatus", {}).get(idx, 1)
        status_str = "up" if status_val == 1 else "down"

        # ifAdminStatus: 1=up, 2=down(admin shutdown), 3=testing
        is_admin_down = admin_val == 2

        # ดึง IP จาก map (ค้นหาด้วย ifIndex)
        ip = ip_map.get(idx, "unassigned")

        # ดึงค่าจาก Cisco private MIB (อาจเป็นค่าขยะจาก GNS3)
        raw_rxload = data.get("locIfInLoad", {}).get(idx)
        raw_txload = data.get("locIfOutLoad", {}).get(idx)
        raw_reliability = data.get("locIfReliability", {}).get(idx, 255)

        # Sanitize: ค่าต้องอยู่ในช่วง 0-255
        # ถ้า GNS3 ส่งค่าขยะ (เกิน 255 หรือ reliability=0 ทั้งที่ up) ให้ใช้ค่า default
        speed_bps = _interface_speed_bps(data, idx)
        rxload = (
            raw_rxload
            if _valid_load(raw_rxload)
            else _octet_load(host, idx, "in", data.get("ifInOctets", {}).get(idx), speed_bps, now)
        )
        txload = (
            raw_txload
            if _valid_load(raw_txload)
            else _octet_load(host, idx, "out", data.get("ifOutOctets", {}).get(idx), speed_bps, now)
        )
        reliability = raw_reliability if 0 < raw_reliability <= 255 else 255

        # ถ้า interface up แต่ reliability=0 แสดงว่า SNMP ส่งค่าขยะ → ใช้ค่า default
        if status_val == 1 and raw_reliability == 0:
            reliability = 255

        interfaces.append(
            {
                "intf": str(name),
                "ip": ip,
                "status": "admin_down" if is_admin_down else status_str,
                "protocol": status_str,
                "rxload": rxload,
                "network_load": txload,
                "reliability": reliability,
                "input_errors": data.get("ifInErrors", {}).get(idx, 0),
                "is_admin_down": is_admin_down,
            }
        )

    # ── GNS3 Cold-Start Junk Detection ──────────────────────────────
    # ถ้า interface ที่ up ทั้งหมดมีค่า rxload หรือ txload เท่ากันหมด
    # และค่านั้นสูงผิดปกติ (>20) → แสดงว่าเป็นค่าขยะจาก GNS3 ตอนเพิ่งบูท
    # เพราะในโลกจริง traffic แต่ละพอร์ตจะต่างกันเสมอ ไม่มีทางเท่ากันหมด
    up_intfs = [i for i in interfaces if i["status"] == "up"]
    if len(up_intfs) >= 2:
        rx_vals = [i["rxload"] for i in up_intfs]
        tx_vals = [i["network_load"] for i in up_intfs]

        # ตรวจค่า rxload: ถ้าทุกตัวเท่ากันหมด และ > 20 → ค่าขยะ
        if len(set(rx_vals)) == 1 and rx_vals[0] > 20:
            log.warning(f"GNS3 junk detected on {host}: all rxload={rx_vals[0]}, resetting to 1")
            for i in interfaces:
                i["rxload"] = 1

        # ตรวจค่า txload: ถ้าทุกตัวเท่ากันหมด และ > 20 → ค่าขยะ
        if len(set(tx_vals)) == 1 and tx_vals[0] > 20:
            log.warning(f"GNS3 junk detected on {host}: all txload={tx_vals[0]}, resetting to 1")
            for i in interfaces:
                i["network_load"] = 1

        # ── Enhanced: TX≈0 แต่ RX สูงผิดปกติบนหลาย interface → ค่าขยะจาก GNS3 ──
        # หลัง port bounce GNS3 อาจคืนค่า locIfInLoad สูงแต่ไม่เท่ากัน
        # ในโลกจริง ถ้า TX≈0 ทุก interface แล้ว RX สูง >20% บนส่วนใหญ่ ไม่สมเหตุสมผล
        all_tx_low = all(v <= 5 for v in tx_vals)
        high_rx_count = sum(1 for v in rx_vals if v > 20)
        if all_tx_low and high_rx_count >= len(up_intfs) * 0.5:
            log.warning(f"GNS3 junk detected on {host}: TX≈0 but RX high on {high_rx_count}/{len(up_intfs)} intfs {rx_vals}, resetting RX to 1")
            for i in interfaces:
                if i["status"] == "up":
                    i["rxload"] = 1

    return interfaces


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = get_snmp_interfaces("10.10.100.1", "public")
    for r in result:
        print(f"  {r['intf']:20s} | IP: {r['ip']:16s} | {r['status']:6s} | admin_down={r['is_admin_down']}")

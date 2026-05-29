# Import required libraries for network device data collection
from netmiko import ConnectHandler  # Library for SSH/Telnet connections to network devices
from app.db import save_log  # Function for saving collected logs to database
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml  # For reading configuration files
import re  # For text processing using regular expressions
import time  # For handling delays
import os
import logging
from dotenv import load_dotenv
from app import collector_rules
from app.security import device_credential
from app.snmp_helper import get_snmp_interfaces
from app.simulator import simulated_interfaces, simulator_enabled

load_dotenv()
log = logging.getLogger(__name__)

# Read configuration settings from config.yaml
with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

# Read device configurations from devices.yaml
with open("config/devices.yaml", "r", encoding="utf-8") as f:
    devices_config = yaml.safe_load(f)

# Extract configurations from config file
SKIP_TYPES = [
    s for s in config["anomaly"]["skip_types"] if s is not None
]  # Types of interfaces to skip
THRESHOLD_LOAD = config["model"]["threshold_load"]  # Threshold for network load
THRESHOLD_RELIABILITY = config["model"]["threshold_reliability"]  # Threshold for reliability
THRESHOLD_ERRORS = config["model"]["threshold_errors"]  # Threshold for input errors
MAX_RETRIES = 3  # Maximum retry attempts
RETRY_DELAY = 5  # Timeout delay between retries (seconds)

# -- Link Type rules from config (avoid hardcoding IP) ------------------------
LINK_TYPE_RULES = config.get("link_types", {}).get("rules", [])
LINK_TYPE_DEFAULT = config.get("link_types", {}).get("default", "Other")


def infer_device_role(device):
    return collector_rules.infer_device_role(device)


def infer_interface_role(device, intf, data):
    return collector_rules.infer_interface_role(device, intf, data)


def upstream_devices(device):
    return collector_rules.upstream_devices(device)


def get_device_credentials(device):
    """Retrieve credentials from device config or default .env variables."""
    return {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": device_credential(device, "username", "DEVICE_USERNAME"),
        "password": device_credential(device, "password", "DEVICE_PASSWORD"),
        "secret": device_credential(device, "secret", "DEVICE_SECRET"),
    }


def should_skip(intf, ip, is_admin_down):
    return collector_rules.should_skip(intf, ip, is_admin_down, SKIP_TYPES)


def get_link_type(ip):
    return collector_rules.get_link_type(ip, LINK_TYPE_RULES, LINK_TYPE_DEFAULT)


def parse_interfaces(raw):
    """Parse output from show interfaces command into a structured data dictionary."""
    result = {}
    current = None
    for line in raw.splitlines():
        # Identify interface status line
        m = re.match(r"^(\S+)\s+is\s+(.+),\s+line protocol is\s+(\S+)", line)
        if m:
            current = m.group(1)
            result[current] = {
                "phys": m.group(2).strip(),  # Physical status
                "proto": m.group(3).strip(),  # Protocol status
                "reliability": "255",  # Reliability rating (default 255)
                "txload": "1",  # Output load (default 1)
                "rxload": "1",  # Input load (default 1)
                "input_errors": "0",  # Input errors count (default 0)
            }
        if current:
            # Find reliability, txload, and rxload parameters
            r = re.search(r"reliability (\d+)/255,\s*txload (\d+)/255,\s*rxload (\d+)/255", line)
            if r:
                result[current]["reliability"] = r.group(1)
                result[current]["txload"] = r.group(2)
                result[current]["rxload"] = r.group(3)
            # Find input errors
            e = re.search(r"(\d+) input errors", line)
            if e:
                result[current]["input_errors"] = e.group(1)
    return result


# -- Label classification function (normal/anomaly) --------------------------
def get_label(status_num, protocol_num, network_load, rxload, reliability, input_errors, is_admin_down):
    return collector_rules.get_label(
        status_num,
        protocol_num,
        network_load,
        rxload,
        reliability,
        input_errors,
        is_admin_down,
        THRESHOLD_LOAD,
        THRESHOLD_RELIABILITY,
        THRESHOLD_ERRORS,
    )


def collect_device(device, on_timeout=None):
    """Collect all interface data from a single device using SNMP/Simulation."""
    host = device["host"]
    community = device.get("snmp_community", os.getenv("SNMP_COMMUNITY", "public"))

    for attempt in range(MAX_RETRIES):
        try:
            results = []

            # Retrieve data through SNMP or fallback to simulated data for demo
            if simulator_enabled(config) or device.get("simulate"):
                interfaces_data = simulated_interfaces(device, config)
            else:
                oid_overrides = device.get("snmp_oids") or config.get("snmp", {}).get("oids")
                interfaces_data = get_snmp_interfaces(host, community, oid_overrides=oid_overrides)

            for data in interfaces_data:
                intf = data["intf"]
                ip = data["ip"]
                is_admin_down = data.get("is_admin_down", False)

                if should_skip(intf, ip, is_admin_down):
                    continue

                status_num = 0 if (is_admin_down or data["status"] == "down") else 1
                protocol_num = 1 if data["protocol"] == "up" else 0

                reliability = int(data["reliability"])
                network_load = int(data["network_load"])
                rxload = int(data["rxload"])
                input_errors = int(data["input_errors"])
                link_type = get_link_type(ip)
                device_role = infer_device_role(device)
                interface_role = infer_interface_role(device, intf, data)
                upstream = upstream_devices(device)

                label = get_label(
                    status_num, protocol_num, network_load, rxload, reliability, input_errors, is_admin_down
                )

                log_id = save_log(
                    device["name"],
                    intf,
                    ip,
                    data["status"],
                    data["protocol"],
                    reliability,
                    network_load,
                    rxload,
                    input_errors,
                    link_type,
                    device.get("zone", "Unknown"),
                    device.get("location", "Unknown"),
                    label,
                )

                results.append(
                    {
                        "log_id": log_id,
                        "device": device["name"],
                        "intf": intf,
                        "ip": ip,
                        "status_num": status_num,
                        "protocol_num": protocol_num,
                        "reliability": reliability,
                        "network_load": network_load,
                        "rxload": rxload,
                        "input_errors": input_errors,
                        "link_type": link_type,
                        "label": label,
                        "is_admin_down": is_admin_down,
                        "device_role": device_role,
                        "interface_role": interface_role,
                        "upstream_devices": upstream,
                        "zone": device.get("zone", "Unknown"),
                        "location": device.get("location", "Unknown"),
                    }
                )

            # When collection succeeds -> update record ALL to 'up' status (in case it was down)
            save_log(
                device["name"],
                "ALL",
                host,
                "up",
                "up",
                255,
                0,
                0,
                0,
                "Unknown",
                device.get("zone", "Unknown"),
                device.get("location", "Unknown"),
                "normal",
            )

            log.info(f"{device['name']}: Collected {len(results)} interfaces")
            return results

        except Exception as e:
            # Handle retry logic if device connection fails
            if attempt < MAX_RETRIES - 1:
                log.warning(f"{device['name']} retry {attempt+1}/{MAX_RETRIES}: {e}")
                time.sleep(RETRY_DELAY)
            else:
                log.error(f"{device['name']}: Retries exhausted — {e}")
                # Invoke timeout callback if provided
                if on_timeout:
                    on_timeout(
                        {
                            "device": device["name"],
                            "host": device["host"],
                            "zone": device.get("zone", "Unknown"),
                            "error": str(e),
                        }
                    )

                # Save a record indicating device is down so predictor can detect it
                log_id = save_log(
                    device["name"],
                    "ALL",
                    device["host"],
                    "down",
                    "down",
                    0,
                    0,
                    0,
                    0,
                    "Unknown",
                    device.get("zone", "Unknown"),
                    device.get("location", "Unknown"),
                    "anomaly",
                )
                return [
                    {
                        "log_id": log_id,
                        "device": device["name"],
                        "intf": "ALL",
                        "ip": device["host"],
                        "status_num": 0,
                        "protocol_num": 0,
                        "reliability": 0,
                        "network_load": 0,
                        "rxload": 0,
                        "input_errors": 0,
                        "link_type": "Unknown",
                        "label": "anomaly",
                        "is_admin_down": False,
                        "is_device_down": True,
                        "error": str(e),
                        "device_role": infer_device_role(device),
                        "interface_role": "device",
                        "upstream_devices": upstream_devices(device),
                        "zone": device.get("zone", "Unknown"),
                        "location": device.get("location", "Unknown"),
                    }
                ]

    return []


# -- Multithreaded collection function for all devices ------------------------
def collect_all(on_timeout=None):
    """Collect interface data from all configured devices concurrently using ThreadPoolExecutor."""
    all_results = []
    devices = devices_config["devices"]
    max_workers = min(len(devices), 8)  # limit to max 8 concurrent threads

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(collect_device, device, on_timeout): device["name"] for device in devices}
        for future in as_completed(futures):
            device_name = futures[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                log.error(f"{device_name}: ThreadPool error — {e}")

    return all_results

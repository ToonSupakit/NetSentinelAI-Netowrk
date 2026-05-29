import os
from dotenv import load_dotenv
from netmiko import ConnectHandler
import yaml

load_dotenv()

# Load devices
with open("config/devices.yaml", "r") as f:
    config = yaml.safe_load(f)

devices = config.get("devices", [])
username = os.getenv("DEVICE_USERNAME", "admin")
password = os.getenv("DEVICE_PASSWORD", "admin123")
secret = os.getenv("DEVICE_SECRET", "admin123")

commands_to_run = [
    "show ip interface brief",
    "show ip route",
    "show processes cpu sorted | exclude 0.00%",
    "show logging | include CPU|Memory|Traceback|Interface"
]

print("--- Network Diagnostic Tool ---")
print("Connecting to devices to check routing and CPU state...\n")

for dev in devices:
    print(f"[*] Checking {dev['name']} ({dev['host']})...")
    
    device_params = {
        "device_type": dev.get("device_type", "cisco_ios_telnet"),
        "host": dev["host"],
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 10,
    }
    
    try:
        net_connect = ConnectHandler(**device_params)
        net_connect.enable()
        
        for cmd in commands_to_run:
            print(f"  > Output for: {cmd}")
            output = net_connect.send_command(cmd)
            # Print first 10 lines to avoid spamming the console
            lines = output.splitlines()
            for line in lines[:10]:
                print(f"    {line}")
            if len(lines) > 10:
                print(f"    ... (and {len(lines) - 10} more lines)")
            print("-" * 40)
            
        net_connect.disconnect()
        print(f"[+] Successfully checked {dev['name']}\n")
    except Exception as e:
        print(f"[-] Failed to connect to {dev['name']}: {str(e)}\n")

print("--- Diagnostic Complete ---")

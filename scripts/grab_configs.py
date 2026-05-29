import os
from netmiko import ConnectHandler
import yaml
from dotenv import load_dotenv

load_dotenv()

with open("config/devices.yaml", "r") as f:
    config = yaml.safe_load(f)

devices = config.get("devices", [])
username = os.getenv("DEVICE_USERNAME", "admin")
password = os.getenv("DEVICE_PASSWORD", "admin")
secret = os.getenv("DEVICE_SECRET", "admin")

os.makedirs("scratch", exist_ok=True)

for dev in devices:
    if dev['name'] not in ("ESW1", "ESW2"):
        continue
    print(f"Grabbing config from {dev['name']} at {dev['host']}...")
    try:
        net_connect = ConnectHandler(
            device_type="cisco_ios_telnet",
            host=dev["host"],
            username=username,
            password=password,
            secret=secret,
            timeout=10,
        )
        net_connect.enable()
        
        # Grab running config
        run_conf = net_connect.send_command("show run")
        print(f"\n=== {dev['name']} RUNNING CONFIG ===")
        print(run_conf)
        
        with open(f"scratch/{dev['name']}_run.txt", "w") as f:
            f.write(run_conf)
            
        net_connect.disconnect()
        print(f"  -> Saved {dev['name']} config.")
    except Exception as e:
        print(f"  -> Failed to connect to {dev['name']}: {e}")

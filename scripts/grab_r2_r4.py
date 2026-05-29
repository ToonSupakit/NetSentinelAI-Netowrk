import os
from netmiko import ConnectHandler

devices = [
    {"name": "R2", "host": "192.168.189.10"},
    {"name": "R4", "host": "192.168.189.20"}
]
username = "admin"
password = "admin123"
secret = "admin123"

os.makedirs("scratch", exist_ok=True)

for dev in devices:
    print(f"Connecting to {dev['name']} via {dev['host']}...")
    try:
        net_connect = ConnectHandler(
            device_type="cisco_ios_telnet",
            host=dev["host"],
            username=username,
            password=password,
            secret=secret,
            timeout=15,
        )
        net_connect.enable()
        
        cmds = ["show run", "show ip route", "show ip ospf database"]
        for cmd in cmds:
            out = net_connect.send_command(cmd)
            with open(f"scratch/{dev['name']}_{cmd.replace(' ', '_')}.txt", "w") as f:
                f.write(out)
                
        net_connect.disconnect()
        print(f"  -> Saved {dev['name']} output.")
    except Exception as e:
        print(f"  -> Failed: {e}")

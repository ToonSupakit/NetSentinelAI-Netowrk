import time
import subprocess
from netmiko import ConnectHandler

device_params = {
    "device_type": "cisco_ios_telnet",
    "host": "192.168.189.10",
    "username": "admin",
    "password": "admin123",
    "secret": "admin123",
    "timeout": 15,
}

try:
    print("1. Ping R2 before shutdown...")
    res = subprocess.run(["ping", "-n", "2", "192.168.189.10"], capture_output=True, text=True)
    print("Ping output:", "Reply from" in res.stdout)
    
    print("\n2. Connecting to R2 to shutdown f1/0...")
    net_connect = ConnectHandler(**device_params)
    net_connect.enable()
    
    out = net_connect.send_config_set(["interface f1/0", "shutdown"])
    print(out)
    
    print("\n3. Waiting 5 seconds...")
    time.sleep(5)
    
    print("\n4. Checking CPU usage...")
    out = net_connect.send_command("show processes cpu sorted | ex 0.00%")
    print(out)
    
    print("\n5. Bringing f1/0 back up...")
    out = net_connect.send_config_set(["interface f1/0", "no shutdown"])
    print(out)
    
    net_connect.disconnect()
except Exception as e:
    print(f"\nFATAL ERROR: {str(e)}")
    print("This means the router froze and dropped the Telnet connection!")
    
print("\n6. Ping R2 after test...")
res = subprocess.run(["ping", "-n", "2", "192.168.189.10"], capture_output=True, text=True)
print("Ping output:", "Reply from" in res.stdout)

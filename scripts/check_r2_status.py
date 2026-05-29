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
    print("Connecting to R2 (192.168.189.10)...")
    net_connect = ConnectHandler(**device_params)
    net_connect.enable()
    
    out = net_connect.send_command("show ip interface brief")
    print("--- R2 Interfaces ---")
    print(out)
    
    out = net_connect.send_command("show run interface f1/0")
    print("--- R2 f1/0 Config ---")
    print(out)
    
    net_connect.disconnect()
except Exception as e:
    print(f"Error connecting to R2: {str(e)}")

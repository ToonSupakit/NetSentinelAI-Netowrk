from netmiko import ConnectHandler

device_params = {
    "device_type": "cisco_ios_telnet",
    "host": "192.168.189.20",  # Connect to R4
    "username": "admin",
    "password": "admin123",
    "secret": "admin123",
    "timeout": 15,
}

try:
    print("Connecting to R4 (192.168.189.20)...")
    net_connect = ConnectHandler(**device_params)
    net_connect.enable()
    
    print("--- Ping R2 Physical IP (192.168.189.10) ---")
    print(net_connect.send_command("ping 192.168.189.10"))
    
    print("\n--- Show IP ARP ---")
    print(net_connect.send_command("show ip arp"))
    
    net_connect.disconnect()
except Exception as e:
    print(f"Error connecting to R4: {str(e)}")

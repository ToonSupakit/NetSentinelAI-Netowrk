from netmiko import ConnectHandler

device_params = {
    "device_type": "cisco_ios_telnet",
    "host": "192.168.189.20",  # Connect to R4 physical IP (since it is reachable)
    "username": "admin",
    "password": "admin123",
    "secret": "admin123",
    "timeout": 10,
}

try:
    print("Connecting to R4 (192.168.189.20)...")
    net_connect = ConnectHandler(**device_params)
    net_connect.enable()
    
    print("--- Ping R2 Management IP (192.168.189.10) ---")
    print(net_connect.send_command("ping 192.168.189.10"))
    
    print("\n--- Ping R2 Loopback (10.10.100.2) ---")
    print(net_connect.send_command("ping 10.10.100.2"))

    print("\n--- Show OSPF neighbors ---")
    print(net_connect.send_command("show ip ospf neighbor"))

    print("\n--- Show IP Route ---")
    print(net_connect.send_command("show ip route"))

    net_connect.disconnect()
except Exception as e:
    print(f"Error connecting to R4: {str(e)}")

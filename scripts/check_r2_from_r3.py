from netmiko import ConnectHandler

device_params = {
    "device_type": "cisco_ios_telnet",
    "host": "10.10.100.3",  # Connect to R3
    "username": "admin",
    "password": "admin123",
    "secret": "admin123",
    "timeout": 10,
}

try:
    net_connect = ConnectHandler(**device_params)
    net_connect.enable()
    
    print("Pinging R2 loopback (10.10.100.2) from R3...")
    output = net_connect.send_command("ping 10.10.100.2")
    print(output)

    print("\nPinging R2 f1/2 (192.168.189.10) from R3...")
    output = net_connect.send_command("ping 192.168.189.10")
    print(output)

    net_connect.disconnect()
except Exception as e:
    print(f"Error connecting to R3: {str(e)}")

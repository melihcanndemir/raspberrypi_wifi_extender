import subprocess

def validate_input(ssid, passphrase):
    if len(ssid) < 1:
        raise ValueError("SSID cannot be empty.")
    if len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters long.")

def update_system():
    print("Updating system packages...")
    subprocess.run(["sudo", "apt-get", "update"])

def install_packages():
    print("Installing required packages...")
    subprocess.run(["sudo", "apt-get", "install", "-y", "hostapd", "dnsmasq"])

def write_hostapd_conf(ssid, passphrase, interface="wlan0"):
    print("Writing hostapd configuration...")
    hostapd_conf_content = f"""
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={passphrase}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
    """
    with open("/etc/hostapd/hostapd.conf", "w") as f:
        f.write(hostapd_conf_content)

def configure_hostapd():
    print("Configuring hostapd...")
    subprocess.run(["sudo", "systemctl", "unmask", "hostapd"])
    subprocess.run(["sudo", "systemctl", "enable", "hostapd"])

def write_dnsmasq_conf(dhcp_start, dhcp_end, netmask="255.255.255.0"):
    print("Writing dnsmasq configuration...")
    dnsmasq_conf_content = f"""
interface=wlan0
dhcp-range={dhcp_start},{dhcp_end},{netmask},12h
    """
    with open("/etc/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf_content)

def configure_dhcpcd(interface, ip_address):
    print("Configuring dhcpcd...")
    dhcpcd_conf_content = f"""
interface {interface}
static ip_address={ip_address}
    """
    with open("/etc/dhcpcd.conf", "a") as f:
        f.write(dhcpcd_conf_content)

def enable_ip_forwarding():
    print("Enabling IP forwarding...")
    with open("/etc/sysctl.conf", "a") as f:
        f.write("\nnet.ipv4.ip_forward=1\n")
    subprocess.run(["sudo", "sysctl", "-p", "/etc/sysctl.conf"])

def configure_iptables():
    print("Configuring iptables...")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", "eth0", "-o", "wlan0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", "wlan0", "-o", "eth0", "-j", "ACCEPT"])

def start_services():
    print("Starting services...")
    subprocess.run(["sudo", "systemctl", "start", "dnsmasq"])
    subprocess.run(["sudo", "systemctl", "restart", "dhcpcd"])
    subprocess.run(["sudo", "systemctl", "restart", "hostapd"])

def revert_changes():
    print("Reverting changes...")
    subprocess.run(["sudo", "systemctl", "stop", "hostapd"])
    subprocess.run(["sudo", "systemctl", "disable", "hostapd"])
    subprocess.run(["sudo", "rm", "/etc/hostapd/hostapd.conf"])
    subprocess.run(["sudo", "systemctl", "stop", "dnsmasq"])
    subprocess.run(["sudo", "systemctl", "restart", "dhcpcd"])

def show_status():
    print("Showing status...")
    subprocess.run(["sudo", "systemctl", "status", "hostapd"])
    subprocess.run(["sudo", "systemctl", "status", "dnsmasq"])
    subprocess.run(["sudo", "systemctl", "status", "dhcpcd"])

def main():
    while True:
        print("\nWiFi Extender Tool Menu:")
        print("1. Setup WiFi Extender")
        print("2. Revert Changes")
        print("3. Check Status")
        print("4. Exit")
        
        choice = input("Enter your choice (1/2/3/4): ")
        
        if choice == "1":
            ssid = input("Enter the SSID for your hotspot: ")
            passphrase = input("Enter the passphrase for your hotspot: ")
            interface = input("Enter the network interface for your hotspot (default is wlan0): ") or "wlan0"
            ip_address = input("Enter the IP address for your hotspot (default is 192.168.50.1/24): ") or "192.168.50.1/24"
            dhcp_start = input("Enter the DHCP range start (default is 192.168.50.10): ") or "192.168.50.10"
            dhcp_end = input("Enter the DHCP range end (default is 192.168.50.50): ") or "192.168.50.50"
            netmask = input("Enter the DHCP netmask (default is 255.255.255.0): ") or "255.255.255.0"
            
            validate_input(ssid, passphrase)
            
            update_system()
            install_packages()
            write_hostapd_conf(ssid, passphrase, interface)
            configure_hostapd()
            write_dnsmasq_conf(dhcp_start, dhcp_end, netmask)
            configure_dhcpcd(interface, ip_address)
            enable_ip_forwarding()
            configure_iptables()
            start_services()
            
            print("Hotspot setup is complete. Your Raspberry Pi is now a WiFi extender.")
        
        elif choice == "2":
            revert_changes()
        
        elif choice == "3":
            show_status()
        
        elif choice == "4":
            print("Exiting WiFi Extender Tool.")
            break
        
        else:
            print("Invalid choice. Please enter a valid option (1-4).")

if __name__ == "__main__":
    main()

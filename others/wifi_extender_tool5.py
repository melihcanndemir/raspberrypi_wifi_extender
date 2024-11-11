import subprocess
import os
import sys
import logging
from colorama import init, Fore
from pyfiglet import Figlet
import shutil
import yaml
import argparse

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='wifi_extender.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom figlet font
custom_fig = Figlet(font='slant')

config = {}

def load_config():
    global config
    try:
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)
    except FileNotFoundError:
        logging.error("config.yaml file not found. Using default values.")
        return config
    except yaml.YAMLError as e:
        logging.error(f"Error parsing config.yaml: {e}")
    return config

def validate_ssid(ssid):
    if not ssid or len(ssid) > 32:
        return False
    return True

def validate_passphrase(passphrase):
    if len(passphrase) < 8 or len(passphrase) > 63:
        return False
    return True

def run_command(command, timeout=60):
    """Helper function to run shell commands with timeout."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"Command '{command}' failed with error: {result.stderr}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command '{command}' timed out after {timeout} seconds")
    except Exception as e:
        raise RuntimeError(f"Error running command '{command}': {str(e)}")

def update_system():
    """Update system packages."""
    logging.info("Updating system packages...")
    print(Fore.GREEN + "\n\nUpdating system packages...")
    run_command("sudo apt-get update && sudo apt-get full-upgrade -y")

def install_packages():
    """Install required packages."""
    logging.info("Installing required packages...")
    print(Fore.GREEN + "Installing required packages...")
    run_command("sudo apt-get install -y hostapd dnsmasq dhcpcd iptables")

def write_hostapd_conf(ssid=None, passphrase=None, interface=None, channel=None, hw_mode=None, ieee80211n=None, ieee80211ac=None):
    """Write hostapd configuration."""
    logging.info("Writing hostapd configuration...")
    print(Fore.GREEN + "Writing hostapd configuration...")

    # Use values from config if not provided
    ssid = ssid or config.get('default_ssid', "RaspberryPi4B")
    passphrase = passphrase or config.get('default_passphrase', "raspberrypi")
    interface = interface or config.get('default_interface', "wlan1")
    channel = channel or config.get('default_channel', 9)
    hw_mode = hw_mode or config.get('default_hw_mode', "g")
    ieee80211n = ieee80211n or config.get('default_ieee80211n', 1)
    ieee80211ac = ieee80211ac or config.get('default_ieee80211ac', 1)

    hostapd_conf_content = f"""interface={interface}
ssid={ssid}
wpa_passphrase={passphrase}
country_code=TR
hw_mode={hw_mode}
channel={channel}
ieee80211n={ieee80211n}
ieee80211ac={ieee80211ac}
wmm_enabled=1
ht_capab=[HT40+][SHORT-GI-20][DSSS_CCK-40]
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    hostapd_conf_path = "/etc/hostapd/hostapd.conf"
    try:
        result = subprocess.run(f"sudo sh -c 'echo \"{hostapd_conf_content}\" > {hostapd_conf_path}'", 
                                shell=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error writing hostapd.conf: {e}")
        raise

    # Set correct permissions for the file
    run_command(f"sudo chmod 600 {hostapd_conf_path}")
    run_command(f"sudo chown root:root {hostapd_conf_path}")

def configure_hostapd():
    """Configure and enable hostapd service."""
    logging.info("Configuring hostapd...")
    print(Fore.GREEN + "Configuring hostapd...")
    if not os.path.isfile("/etc/hostapd/hostapd.conf"):
        raise RuntimeError("hostapd configuration file not found. Please run write_hostapd_conf first.")

    run_command("sudo systemctl unmask hostapd")
    run_command("sudo systemctl enable hostapd")

def write_dnsmasq_conf(dhcp_start=None, dhcp_end=None, netmask=None):
    """Write dnsmasq configuration."""
    logging.info("Writing dnsmasq configuration...")
    print(Fore.GREEN + "Writing dnsmasq configuration...")

    # Use values from config if not provided
    dhcp_start = dhcp_start or config.get('default_dhcp_start', "192.168.2.2")
    dhcp_end = dhcp_end or config.get('default_dhcp_end', "192.168.2.255")
    netmask = netmask or config.get('default_netmask', "255.255.255.0")

    dnsmasq_conf_content = f"""interface=wlan1
dhcp-range={dhcp_start},{dhcp_end},{netmask},24h
    """
    dnsmasq_conf_path = "/etc/dnsmasq.conf"
    try:
        with open(dnsmasq_conf_path, "w") as f:
            f.write(dnsmasq_conf_content)
    except IOError as e:
        logging.error(f"Error writing dnsmasq.conf: {e}")
        raise

def configure_dhcpcd(interface, ip_address):
    """Configures a static IP address for the Raspberry Pi using dhcpcd.

    Args:
        interface (str): The network interface to configure (e.g., "wlan0").
        ip_address (str): The desired static IP address in CIDR notation (e.g., "192.168.1.10/24").

    Raises:
        RuntimeError: If an error occurs while configuring dhcpcd.
    """

    print(f"Configuring dhcpcd for interface {interface} with IP address {ip_address}...")

    dhcpcd_conf_path = "/etc/dhcpcd.conf"
    dhcpcd_conf_backup = "/etc/dhcpcd.conf.orig"

    try:
        # Check if dhcpcd.conf exists
        if os.path.isfile(dhcpcd_conf_path):
            # Check if backup (dhcpcd.conf.orig) exists
            if not os.path.isfile(dhcpcd_conf_backup):
                # Backup dhcpcd.conf if it doesn't exist
                shutil.copy(dhcpcd_conf_path, dhcpcd_conf_backup)
                print(f"Backed up {dhcpcd_conf_path} to {dhcpcd_conf_backup}")

            # Read existing configuration (if any)
            with open(dhcpcd_conf_path, "r") as f:
                existing_content = f.read()

            # Check if configuration already exists for the specified interface
            if (f"interface {interface}\nstatic ip_address={ip_address}" in existing_content and
                    "nohook wpa_supplicant" in existing_content):
                print(f"Configuration for interface {interface} already exists in dhcpcd.conf. Skipping.")
                return

        else:
            # Create new dhcpcd.conf using dhcpcd.conf.orig as template
            if os.path.isfile(dhcpcd_conf_backup):
                shutil.copy(dhcpcd_conf_backup, dhcpcd_conf_path)
                print(f"Created {dhcpcd_conf_path} from {dhcpcd_conf_backup}")
            else:
                raise RuntimeError(f"{dhcpcd_conf_path} not found and {dhcpcd_conf_backup} does not exist.")

        # Append new configuration if it doesn't exist
        with open(dhcpcd_conf_path, "a+") as f:
            dhcpcd_conf_content = f"""interface {interface}
static ip_address={ip_address}
nohook wpa_supplicant
"""
            f.write(dhcpcd_conf_content)
            print(f"Added dhcpcd configuration for interface {interface} with IP address {ip_address}")

    except Exception as e:
        print(f"Error configuring dhcpcd: {e}")
        raise RuntimeError(f"Failed to configure dhcpcd: {e}")

def enable_ip_forwarding():
    """Enable IP forwarding."""
    logging.info("Enabling IP forwarding...")
    print(Fore.GREEN + "Enabling IP forwarding...")
    try:
        with open("/etc/sysctl.conf", "a") as f:
            f.write("\nnet.ipv4.ip_forward=1\n")
        run_command("sudo sysctl -p")
    except IOError as e:
        logging.error(f"Error enabling IP forwarding: {e}")
        raise

def configure_iptables():
    """Configure iptables for NAT."""
    logging.info("Configuring iptables for NAT...")
    print(Fore.GREEN + "Configuring iptables for NAT...")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    run_command("sudo sh -c 'iptables-save > /etc/iptables.ipv4.nat'")

    try:
        with open("/etc/rc.local", "r") as f:
            rc_local = f.read()
    except IOError as e:
        logging.error(f"Error reading /etc/rc.local: {e}")
        raise

    if "iptables-restore < /etc/iptables.ipv4.nat" not in rc_local:
        rc_local = rc_local.replace("exit 0", "iptables-restore < /etc/iptables.ipv4.nat\nexit 0")
        try:
            with open("/etc/rc.local", "w") as f:
                f.write(rc_local)
        except IOError as e:
            logging.error(f"Error writing /etc/rc.local: {e}")
            raise

def start_services():
    """Start and enable necessary services."""
    logging.info("Starting services...")
    print(Fore.GREEN + "Starting services...")
    run_command("sudo systemctl restart dhcpcd")
    run_command("sudo systemctl restart hostapd")
    run_command("sudo systemctl restart dnsmasq")

def stop_services():
    """Stop necessary services."""
    logging.info("Stopping services...")
    print(Fore.RED + "Stopping services...")
    run_command("sudo systemctl stop hostapd")
    run_command("sudo systemctl stop dnsmasq")
    run_command("sudo systemctl stop dhcpcd")

def backup_configs():
    """Backup configuration files."""
    logging.info("Backing up configuration files...")
    print(Fore.GREEN + "Backing up configuration files...")

    try:
        shutil.copy("/etc/dhcpcd.conf", "/etc/dhcpcd.conf.bak")
        shutil.copy("/etc/hostapd/hostapd.conf", "/etc/hostapd/hostapd.conf.bak")
        shutil.copy("/etc/dnsmasq.conf", "/etc/dnsmasq.conf.bak")
        shutil.copy("/etc/sysctl.conf", "/etc/sysctl.conf.bak")
        shutil.copy("/etc/rc.local", "/etc/rc.local.bak")
        shutil.copy("/etc/iptables.ipv4.nat", "/etc/iptables.ipv4.nat.bak")
    except IOError as e:
        logging.error(f"Error backing up configuration files: {e}")
        raise

def restore_configs():
    """Restore configuration files from backup."""
    logging.info("Restoring configuration files from backup...")
    print(Fore.GREEN + "Restoring configuration files from backup...")

    try:
        shutil.copy("/etc/dhcpcd.conf.bak", "/etc/dhcpcd.conf")
        shutil.copy("/etc/hostapd/hostapd.conf.bak", "/etc/hostapd/hostapd.conf")
        shutil.copy("/etc/dnsmasq.conf.bak", "/etc/dnsmasq.conf")
        shutil.copy("/etc/sysctl.conf.bak", "/etc/sysctl.conf")
        shutil.copy("/etc/rc.local.bak", "/etc/rc.local")
        shutil.copy("/etc/iptables.ipv4.nat.bak", "/etc/iptables.ipv4.nat")
    except IOError as e:
        logging.error(f"Error restoring configuration files: {e}")
        raise

def main():
    load_config()
    parser = argparse.ArgumentParser(description="Raspberry Pi WiFi Extender Tool")
    parser.add_argument("--ssid", type=str, help="SSID for the access point")
    parser.add_argument("--passphrase", type=str, help="Passphrase for the access point")
    parser.add_argument("--interface", type=str, default="wlan1", help="Wireless interface (default: wlan1)")
    parser.add_argument("--channel", type=int, default=9, help="Wireless channel (default: 9)")
    parser.add_argument("--hw_mode", type=str, default="g", help="Hardware mode (default: g)")
    parser.add_argument("--ieee80211n", type=int, default=1, help="Enable 802.11n (default: 1)")
    parser.add_argument("--ieee80211ac", type=int, default=1, help="Enable 802.11ac (default: 1)")
    parser.add_argument("--dhcp_start", type=str, default="192.168.2.2", help="Start range for DHCP (default: 192.168.2.2)")
    parser.add_argument("--dhcp_end", type=str, default="192.168.2.255", help="End range for DHCP (default: 192.168.2.255)")
    parser.add_argument("--netmask", type=str, default="255.255.255.0", help="Netmask for DHCP (default: 255.255.255.0)")
    parser.add_argument("--static_ip", type=str, default="192.168.2.1/24", help="Static IP for the interface (default: 192.168.2.1/24)")
    parser.add_argument("--start", action="store_true", help="Start services")
    parser.add_argument("--stop", action="store_true", help="Stop services")
    parser.add_argument("--backup", action="store_true", help="Backup configuration files")
    parser.add_argument("--restore", action="store_true", help="Restore configuration files from backup")
    parser.add_argument("--update", action="store_true", help="Update system packages")
    parser.add_argument("--install", action="store_true", help="Install required packages")
    args = parser.parse_args()

    try:
        if args.update:
            update_system()
        if args.install:
            install_packages()
        if args.ssid or args.passphrase or args.interface or args.channel or args.hw_mode or args.ieee80211n or args.ieee80211ac:
            write_hostapd_conf(args.ssid, args.passphrase, args.interface, args.channel, args.hw_mode, args.ieee80211n, args.ieee80211ac)
            configure_hostapd()
        if args.dhcp_start or args.dhcp_end or args.netmask:
            write_dnsmasq_conf(args.dhcp_start, args.dhcp_end, args.netmask)
        if args.interface and args.static_ip:
            configure_dhcpcd(args.interface, args.static_ip)
        enable_ip_forwarding()
        configure_iptables()
        
        if args.start:
            start_services()
        
        if args.stop:
            stop_services()
        
        if args.backup:
            backup_configs()
        
        if args.restore:
            restore_configs()

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(Fore.RED + f"An error occurred: {e}")
        sys.exit(1)
        
if __name__ == "__main__":
    main()
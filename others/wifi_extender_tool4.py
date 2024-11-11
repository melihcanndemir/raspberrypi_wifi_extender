import subprocess
import os
import sys
import logging
import random
import string
import shutil
import yaml
import argparse
from colorama import init, Fore
from pyfiglet import Figlet
from tqdm import tqdm
from logging.handlers import RotatingFileHandler

# Initialize colorama for colored output
init(autoreset=True)

# Set up rotating log file handler
log_handler = RotatingFileHandler('wifi_extender.log', maxBytes=10**6, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO,
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
    except yaml.YAMLError as e:
        logging.error(f"Error parsing config.yaml: {e}")

def dependency_checker():
    # Check if required dependencies are installed
    pass

def validate_ssid(ssid):
    if not ssid or len(ssid) > 32:
        return False
    return True

def validate_passphrase(passphrase):
    if len(passphrase) < 8 or len(passphrase) > 63:
        return False
    return True

def generate_random_passphrase(length=12):
    """Generate a random passphrase."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

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
    """Update system packages with progress bar."""
    logging.info("Updating system packages...")
    print(Fore.GREEN + "\n\nUpdating system packages...")
    for _ in tqdm(range(100), desc="Updating"):
        run_command("sudo apt-get update && sudo apt-get full-upgrade -y")

def install_packages():
    """Install required packages with progress bar."""
    logging.info("Installing required packages...")
    print(Fore.GREEN + "Installing required packages...")
    for _ in tqdm(range(100), desc="Installing"):
        run_command("sudo apt-get install -y hostapd dnsmasq dhcpcd iptables")

def write_hostapd_conf(ssid=None, passphrase=None, interface=None, channel=None, hw_mode=None, ieee80211n=None, ieee80211ac=None):
    """Write hostapd configuration."""
    logging.info("Writing hostapd configuration...")
    print(Fore.GREEN + "Writing hostapd configuration...")

    ssid = ssid or config.get('default_ssid', "RaspberryPi4B")
    passphrase = passphrase or config.get('default_passphrase', generate_random_passphrase())
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
    backup_file(hostapd_conf_path)
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

    dhcp_start = dhcp_start or config.get('default_dhcp_start', "192.168.2.2")
    dhcp_end = dhcp_end or config.get('default_dhcp_end', "192.168.2.255")
    netmask = netmask or config.get('default_netmask', "255.255.255.0")

    dnsmasq_conf_content = f"""interface=wlan1
dhcp-range={dhcp_start},{dhcp_end},{netmask},24h
    """
    dnsmasq_conf_path = "/etc/dnsmasq.conf"
    backup_file(dnsmasq_conf_path)
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
        raise RuntimeError(f"Error configuring dhcpcd: {e}")

def configure_nat():
    """Configure NAT and IP forwarding."""
    logging.info("Configuring NAT and IP forwarding...")
    print(Fore.GREEN + "Configuring NAT and IP forwarding...")
    run_command("sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    run_command("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'")

def backup_file(filepath):
    """Backup a file before modifying it."""
    if os.path.exists(filepath):
        backup_path = f"{filepath}.bak"
        shutil.copy(filepath, backup_path)
        logging.info(f"Backed up {filepath} to {backup_path}")
        print(Fore.YELLOW + f"Backed up {filepath} to {backup_path}")

def restore_backup(filepath):
    """Restore a file from its backup."""
    backup_path = f"{filepath}.bak"
    if os.path.exists(backup_path):
        shutil.copy(backup_path, filepath)
        logging.info(f"Restored {filepath} from {backup_path}")
        print(Fore.GREEN + f"Restored {filepath} from {backup_path}")
    else:
        logging.error(f"No backup found for {filepath}")
        print(Fore.RED + f"No backup found for {filepath}")

def detect_network_interfaces():
    """Detect available network interfaces."""
    try:
        interfaces = run_command("ls /sys/class/net").split()
        return interfaces
    except RuntimeError as e:
        logging.error(f"Error detecting network interfaces: {e}")
        raise

def check_dependencies():
    """Check and install required dependencies."""
    logging.info("Checking for required dependencies...")
    print(Fore.GREEN + "Checking for required dependencies...")
    dependencies = ["hostapd", "dnsmasq", "dhcpcd5", "iptables"]
    for dependency in dependencies:
        try:
            run_command(f"dpkg -s {dependency}")
        except RuntimeError:
            logging.info(f"{dependency} not found. Installing...")
            print(Fore.YELLOW + f"{dependency} not found. Installing...")
            run_command(f"sudo apt-get install -y {dependency}")

def main(args):
    try:
        load_config()
        check_dependencies()

        if args.update:
            update_system()

        if args.install:
            install_packages()

        interfaces = detect_network_interfaces()
        print(Fore.GREEN + f"Detected network interfaces: {', '.join(interfaces)}")

        if args.write_hostapd_conf:
            write_hostapd_conf()
        if args.configure_hostapd:
            configure_hostapd()
        if args.write_dnsmasq_conf:
            write_dnsmasq_conf()
        if args.configure_dhcpcd:
            configure_dhcpcd(args.interface, args.ip_address)
        if args.configure_nat:
            configure_nat()
        if args.restore_backup:
            restore_backup(args.restore_backup)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiFi Extender Setup Script")
    parser.add_argument("--update", action="store_true", help="Update system packages")
    parser.add_argument("--install", action="store_true", help="Install required packages")
    parser.add_argument("--write_hostapd_conf", action="store_true", help="Write hostapd configuration")
    parser.add_argument("--configure_hostapd", action="store_true", help="Configure hostapd service")
    parser.add_argument("--write_dnsmasq_conf", action="store_true", help="Write dnsmasq configuration")
    parser.add_argument("--configure_dhcpcd", action="store_true", help="Configure dhcpcd for static IP")
    parser.add_argument("--interface", type=str, help="Network interface for dhcpcd configuration")
    parser.add_argument("--ip_address", type=str, help="Static IP address for dhcpcd configuration")
    parser.add_argument("--configure_nat", action="store_true", help="Configure NAT and IP forwarding")
    parser.add_argument("--restore_backup", type=str, help="Restore backup for specified file")

    args = parser.parse_args()
    main(args)
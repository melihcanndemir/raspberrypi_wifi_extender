import subprocess
import os
import sys
import logging
from colorama import init, Fore
from pyfiglet import Figlet
import shutil

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='wifi_extender.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom figlet font
custom_fig = Figlet(font='slant')

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

def write_hostapd_conf(ssid="RaspberryPi4B", passphrase="raspberrypi", interface="wlan1", channel=9, hw_mode="g", ieee80211n="1", ieee80211ac="1"):
    """Write hostapd configuration."""
    logging.info("Writing hostapd configuration...")
    print(Fore.GREEN + "Writing hostapd configuration...")

    # Default values if not provided by user
    if not ssid:
        ssid = "RaspberryPi4B"
    if not passphrase:
        passphrase = "raspberrypi"

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

def write_dnsmasq_conf(dhcp_start="192.168.2.2", dhcp_end="192.168.2.255", netmask="255.255.255.0"):
    """Write dnsmasq configuration."""
    logging.info("Writing dnsmasq configuration...")
    print(Fore.GREEN + "Writing dnsmasq configuration...")

    # Default values if not provided by user
    if not dhcp_start:
        dhcp_start = "192.168.2.2"
    if not dhcp_end:
        dhcp_end = "192.168.2.255"
    if not netmask:
        netmask = "255.255.255.0"

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
        run_command("sudo sysctl -p /etc/sysctl.conf")
    except Exception as e:
        logging.error(f"Error modifying sysctl.conf: {e}")
        raise

def configure_iptables():
    """Configure iptables rules for NAT."""
    logging.info("Configuring iptables...")
    print(Fore.GREEN + "Configuring iptables...")
    run_command("sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")
    run_command("sudo iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run_command("sudo iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT")
    # Save iptables rules
    run_command("sudo sh -c 'iptables-save > /etc/iptables.ipv4.nat'")

def start_services():
    """Start necessary services."""
    logging.info("Starting services...")
    print(Fore.GREEN + "Starting services...")
    run_command("sudo systemctl start dnsmasq")
    run_command("sudo systemctl restart dhcpcd")
    run_command("sudo systemctl restart hostapd")

def stop_services():
    """Stop all services."""
    logging.info("Stopping services...")
    print(Fore.GREEN + "Stopping services...")
    run_command("sudo systemctl stop hostapd")
    run_command("sudo systemctl stop dnsmasq")
    run_command("sudo systemctl stop dhcpcd")

def cleanup():
    """Clean up temporary files and configurations."""
    logging.info("Cleaning up...")
    print(Fore.GREEN + "Cleaning up...")
    if os.path.exists("/etc/hostapd/hostapd.conf"):
        run_command("sudo rm /etc/hostapd/hostapd.conf")

def show_status():
    """Show status of all services."""
    logging.info("Showing status...")
    print(Fore.GREEN + "Showing status...")
    print(run_command("sudo systemctl status hostapd"))
    print(run_command("sudo systemctl status dnsmasq"))
    print(run_command("sudo systemctl status dhcpcd"))

def revert_changes():
    """Revert all changes made by the script."""
    logging.info("Reverting changes...")
    stop_services()
    cleanup()
    # Remove added configurations
    run_command("sudo sed -i '/^interface wlan0/d' /etc/dhcpcd.conf")
    run_command("sudo sed -i '/^static ip_address=/d' /etc/dhcpcd.conf")
    run_command("sudo sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf")
    # Flush iptables rules
    run_command("sudo iptables -F")
    run_command("sudo iptables -t nat -F")

def persist_configuration():
    """Make configuration persistent by modifying rc.local."""
    logging.info("Making configuration persistent...")
    print(Fore.GREEN + "Making configuration persistent...")
    rc_local_path = "/etc/rc.local"
    rc_local_content = """
# Start WiFi extender configuration
/usr/bin/python3 /home/pi/raspberrypi_wifi_extender/wifi_extender_tool2.py --persist-config
exit 0
"""
    if os.path.isfile(rc_local_path):
        with open(rc_local_path, "r") as f:
            existing_content = f.read()
            if "# Start WiFi extender configuration" in existing_content:
                print(Fore.YELLOW + "Configuration is already persistent in rc.local.")
                return
            else:
                try:
                    with open(rc_local_path, "a") as f:
                        f.write(rc_local_content)
                    print(Fore.GREEN + "Configuration added to rc.local for persistence.")
                except Exception as e:
                    logging.error(f"Error writing to rc.local: {e}")
                    raise
    else:
        print(Fore.RED + "Error: rc.local file not found. Cannot make configuration persistent.")

def print_banner(text):
    """Print a custom banner."""
    print(Fore.CYAN + custom_fig.renderText(text))

def get_valid_input(prompt, validator):
    """Get user input with validation."""
    while True:
        user_input = input(prompt).strip()
        if validator(user_input):
            return user_input
        else:
            print(Fore.RED + "Invalid input. Please try again.")

def restart_services():
    """Restart all services."""
    logging.info("Restarting services...")
    print(Fore.GREEN + "Restarting services...")
    run_command("sudo systemctl restart hostapd")
    run_command("sudo systemctl restart dnsmasq")
    run_command("sudo systemctl restart dhcpcd")

def main():
    os.system("clear")
    """Main function to run the WiFi extender setup."""
    try:
        print_banner("Wi-Fi Extender Tool Pro")
        while True:
            print(Fore.LIGHTGREEN_EX + "\nMenu Options:")
            print(Fore.YELLOW + "\n1. Setup WiFi Extender")
            print(Fore.YELLOW + "2. Revert Changes")
            print(Fore.YELLOW + "3. Check Status")
            print(Fore.YELLOW + "4. Make Configuration Persistent")
            print(Fore.YELLOW + "5. Restart Services")
            print(Fore.YELLOW + "6. Exit\n")

            choice = get_valid_input(Fore.LIGHTGREEN_EX +"Enter your choice [1,2,3,4,5,6]: ",
                                        lambda x: x.isdigit() and int(x) in [1, 2, 3, 4, 5, 6])

            if choice == "1":
                ssid = get_valid_input("Enter the SSID for your hotspot: ", validate_ssid)
                passphrase = get_valid_input("Enter the passphrase for your hotspot: ", validate_passphrase)
                interface = get_valid_input("Enter the network interface for your hotspot (default is wlan1): ",
                                                lambda x: x or "wlan1")
                ip_address = get_valid_input("Enter the IP address for your hotspot (default is 192.168.2.1/24): ",
                                                lambda x: x or "192.168.2.1/24")
                dhcp_start = get_valid_input("Enter the DHCP range start (default is 192.168.2.2): ",
                                                lambda x: x or "192.168.2.2")
                dhcp_end = get_valid_input("Enter the DHCP range end (default is 192.168.2.255): ",
                                            lambda x: x or "192.168.2.255")
                netmask = get_valid_input("Enter the DHCP netmask (default is 255.255.255.0): ",
                                            lambda x: x or "255.255.255.0")

                update_system()
                install_packages()
                write_hostapd_conf(ssid, passphrase, interface)
                configure_hostapd()
                write_dnsmasq_conf(dhcp_start, dhcp_end, netmask)
                configure_dhcpcd(interface, ip_address)
                enable_ip_forwarding()
                configure_iptables()
                start_services()

                print(Fore.GREEN + "\nHotspot setup is complete. Your Raspberry Pi is now a WiFi extender.")
                logging.info("WiFi extender setup completed successfully.")

            elif choice == "2":
                revert_changes()
                print(Fore.YELLOW + "\nReverted changes. WiFi extender setup undone.")
                logging.info("Changes reverted successfully.")

            elif choice == "3":
                show_status()

            elif choice == "4":
                persist_configuration()
            
            elif choice == "5":
                restart_services()
                print(Fore.GREEN + "\nServices have been restarted.")
                logging.info("Services restarted successfully.")

            elif choice == "6":
                print(Fore.CYAN + "\nExiting WiFi Extender Tool.")
                break

    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting WiFi Extender Tool due to user interruption...\n")
        logging.warning("Script interrupted by user.")
        revert_changes()
        sys.exit(0)

    except Exception as e:
        print(Fore.RED + f"\nAn unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        revert_changes()
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print_banner("Error!")
        print(Fore.RED + "This script must be run as root.")
        sys.exit(1)
    else:
        main()
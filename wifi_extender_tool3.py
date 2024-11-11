<<<<<<< HEAD
#!/usr/bin/python3
import subprocess
import os
import sys
import logging
from colorama import init, Fore
from pyfiglet import Figlet
import shutil
import yaml
import argparse
import shlex

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='wifi_extender.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom figlet font
custom_fig = Figlet(font='slant')

config = {}

def load_config():
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


def run_command(command, timeout=15):
    """Run a shell command with a timeout."""
    try:
        result = subprocess.run(shlex.split(f"sudo {command}"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        result.check_returncode()
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr}")
        raise RuntimeError(f"Command '{command}' failed with error: {e.stderr}")
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out after {timeout} seconds")
        raise RuntimeError(f"Command '{command}' timed out after {timeout} seconds")
    except Exception as e:
        logging.error(f"Error running command '{command}': {e}")
        raise RuntimeError(f"Error running command '{command}': {e}")


def update_system():
    logging.info("Updating system packages...")
    print(Fore.GREEN + "\n\nUpdating system packages...")
    run_command("apt-get update")
    run_command("apt-get full-upgrade -y")

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
        # Use echo and sudo to write the content
        command = f"echo {shlex.quote(hostapd_conf_content)} | sudo tee {hostapd_conf_path}"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        print(Fore.GREEN + f"Successfully wrote to {hostapd_conf_path}")

        # Set correct permissions for the file
        subprocess.run(f"sudo chmod 600 {hostapd_conf_path}", shell=True, check=True)
        subprocess.run(f"sudo chown root:root {hostapd_conf_path}", shell=True, check=True)

    except subprocess.CalledProcessError as e:
        logging.error(f"Error writing or configuring hostapd.conf: {e}")
        print(Fore.RED + f"Error: {e}")
        raise

def configure_hostapd():
    """Configure and enable hostapd service."""
    logging.info("Configuring hostapd...")
    print(Fore.GREEN + "Configuring hostapd...")

    if not os.path.isfile("/etc/hostapd/hostapd.conf"):
        raise RuntimeError("hostapd configuration file not found. Please run write_hostapd_conf first.")

    try:
        subprocess.run("sudo systemctl unmask hostapd", shell=True, check=True)
        subprocess.run("sudo systemctl enable hostapd", shell=True, check=True)
        print(Fore.GREEN + "Successfully configured hostapd")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error configuring hostapd: {e}")
        print(Fore.RED + f"Error: {e}")
        raise

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
        # Use echo and sudo to write the content
        command = f"echo '{dnsmasq_conf_content}' | sudo tee {dnsmasq_conf_path}"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        print(Fore.GREEN + f"Successfully wrote to {dnsmasq_conf_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error writing dnsmasq.conf: {e}")
        print(Fore.RED + f"Error: {e}")
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
    print(Fore.RESET)
    print(Fore.RED + "="*155)
    print(Fore.YELLOW + run_command("sudo systemctl status hostapd"))
    print(Fore.RED + "="*155)
    print(Fore.LIGHTGREEN_EX + run_command("sudo systemctl status dnsmasq"))
    print(Fore.RED + "="*155)
    print(Fore.CYAN + run_command("sudo systemctl status dhcpcd"))
    print(Fore.RED + "="*155)
    input(Fore.GREEN + "\nPress Enter to return to the main menu...")
    os.system("clear")


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

def parse_arguments():
    parser = argparse.ArgumentParser(description='Raspberry Pi WiFi Extender Setup')
    parser.add_argument('--setup', action='store_true', help='Run full setup')
    parser.add_argument('--revert', action='store_true', help='Revert changes')
    parser.add_argument('--status', action='store_true', help='Check status')
    parser.add_argument('--persist', action='store_true', help='Make configuration persistent')
    parser.add_argument('--restart', action='store_true', help='Restart services')
    parser.add_argument('--ssid', type=str, help='SSID for the hotspot')
    parser.add_argument('--passphrase', type=str, help='Passphrase for the hotspot')
    parser.add_argument('--interface', type=str, help='Network interface for the hotspot')
    parser.add_argument('--ip', type=str, help='IP address for the hotspot')
    return parser.parse_args()

def install_system_package(package):
    """Install a system package using apt-get."""
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', package], check=True)
        print(Fore.GREEN + f"{package} has been installed successfully.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"Failed to install {package}.")

def install_python_package(package):
    """Install a Python package using apt-get."""
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', f'python3-{package}'], check=True)
        print(Fore.GREEN + f"{package} has been installed successfully.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"Failed to install {package}.")

def check_system_package(package):
    """Check if a system package is installed."""
    try:
        subprocess.run(['dpkg', '-s', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_python_package(package):
    """Check if a Python package is installed."""
    try:
        subprocess.run(['python3', '-c', f'import {package}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_dependencies():
    print("Wi-Fi Extender Tool Pro Checking Depencies...")
    """Check if required packages are installed."""
    system_packages = ['hostapd', 'dnsmasq', 'dhcpcd', 'iptables']
    python_packages = ['colorama', 'pyfiglet', 'yaml']

    print(Fore.CYAN + "Checking system packages:")
    for package in system_packages:
        if check_system_package(package):
            print(Fore.GREEN + f" - {package} is installed.")
        else:
            print(Fore.RED + f" - {package} is missing. Please install it.")

    print(Fore.CYAN + "\nChecking Python packages:")
    for package in python_packages:
        if check_python_package(package):
            print(Fore.GREEN + f" - {package} is installed.")
        else:
            print(Fore.RED + f" - {package} is missing. Please install it.")

    # Check if any packages are missing
    missing_system_packages = [pkg for pkg in system_packages if not check_system_package(pkg)]
    missing_python_packages = [pkg for pkg in python_packages if not check_python_package(pkg)]

    if missing_system_packages or missing_python_packages:
        print(Fore.RED + "\nThe following packages are missing and need to be installed:")
        
        if missing_system_packages:
            print(Fore.RED + "System packages:")
            for package in missing_system_packages:
                print(Fore.RED + f" - {package}")

        if missing_python_packages:
            print(Fore.RED + "Python packages:")
            for package in missing_python_packages:
                print(Fore.RED + f" - {package}")

        user_input = input(Fore.YELLOW + "\nDo you want to install the missing packages now? (y/n): ").strip().lower()
        if user_input == 'y':
            for package in missing_system_packages:
                install_system_package(package)
            for package in missing_python_packages:
                install_python_package(package)
            print(Fore.GREEN + "All missing packages have been installed. Please run the script again.")
        else:
            print(Fore.RED + "Please install the missing packages and run the script again.")
        sys.exit(1)

def main():
    global config
    config = load_config()
    args = parse_arguments()

    if args.setup:
        ssid = args.ssid or get_valid_input("Enter the SSID for your hotspot: ", validate_ssid)
        passphrase = args.passphrase or get_valid_input("Enter the passphrase for your hotspot: ", validate_passphrase)
        interface = args.interface or get_valid_input(
            f"Enter the network interface for your hotspot (default is {config.get('default_interface', 'wlan1')}): ",
            lambda x: x or config.get('default_interface', 'wlan1')
        )
        ip_address = args.ip or get_valid_input(
            f"Enter the IP address for your hotspot (default is {config.get('default_ip_address', '192.168.2.1/24')}): ",
            lambda x: x or config.get('default_ip_address', '192.168.2.1/24')
        )

        try:
            update_system()
            install_packages()
            write_hostapd_conf(ssid, passphrase, interface)
            configure_hostapd()
            write_dnsmasq_conf()
            configure_dhcpcd(interface, ip_address)
            enable_ip_forwarding()
            configure_iptables()
            start_services()
            print(Fore.GREEN + "\nHotspot setup is complete. Your Raspberry Pi is now a WiFi extender.")
            logging.info("WiFi extender setup completed successfully.")
        except Exception as e:
            logging.error(f"Setup failed: {e}")
            print(Fore.RED + f"Setup failed: {e}")

    elif args.revert:
        try:
            revert_changes()
            print(Fore.YELLOW + "\nReverted changes. WiFi extender setup undone.")
            logging.info("Changes reverted successfully.")
        except Exception as e:
            logging.error(f"Revert failed: {e}")
            print(Fore.RED + f"Revert failed: {e}")

    elif args.status:
        show_status()

    elif args.persist:
        try:
            persist_configuration()
            print(Fore.GREEN + "\nConfiguration is now persistent.")
        except Exception as e:
            logging.error(f"Persisting configuration failed: {e}")
            print(Fore.RED + f"Persisting configuration failed: {e}")

    elif args.restart:
        try:
            restart_services()
            print(Fore.GREEN + "\nServices have been restarted.")
            logging.info("Services restarted successfully.")
        except Exception as e:
            logging.error(f"Restarting services failed: {e}")
            print(Fore.RED + f"Restarting services failed: {e}")

    else:
        # If no arguments are provided, run the interactive menu
        interactive_menu()

def interactive_menu():
    os.system("clear")
    """Main function to run the WiFi extender setup."""
    try:
        # Check dependencies
        check_dependencies()
        input(Fore.YELLOW + "\nPress enter to continue...")
        os.system("clear")
        while True:
            print_banner("Wi-Fi Extender Tool Pro")
            print(Fore.LIGHTGREEN_EX + "\nMenu Options:")
            print(Fore.YELLOW + "\n1. Setup WiFi Extender")
            print(Fore.YELLOW + "2. Revert Changes")
            print(Fore.YELLOW + "3. Check Status")
            print(Fore.YELLOW + "4. Make Configuration Persistent")
            print(Fore.YELLOW + "5. Restart Services")
            print(Fore.YELLOW + "6. About")
            print(Fore.YELLOW + "7. Exit\n")

            choice = get_valid_input(Fore.LIGHTGREEN_EX +"Enter your choice [1,2,3,4,5,6,7]: ",
                                        lambda x: x.isdigit() and int(x) in [1, 2, 3, 4, 5, 6, 7])

            if choice == "1":
                ssid = get_valid_input("Enter the SSID for your hotspot: ", validate_ssid)
                passphrase = get_valid_input("Enter the passphrase for your hotspot: ", validate_passphrase)
                interface = get_valid_input(f"Enter the network interface for your hotspot (default is {config.get('default_interface', 'wlan1')}): ",
                                    lambda x: x or config.get('default_interface', 'wlan1'))
                ip_address = get_valid_input(f"Enter the IP address for your hotspot (default is {config.get('default_ip_address', '192.168.2.1/24')}): ",
                                    lambda x: x or config.get('default_ip_address', '192.168.2.1/24'))
                dhcp_start = get_valid_input(f"Enter the DHCP range start (default is {config.get('default_dhcp_start', '192.168.2.2')}): ",
                                    lambda x: x or config.get('default_dhcp_start', '192.168.2.2'))
                dhcp_end = get_valid_input(f"Enter the DHCP range end (default is {config.get('default_dhcp_end', '192.168.2.255')}): ",
                                    lambda x: x or config.get('default_dhcp_end', '192.168.2.255'))
                netmask = get_valid_input(f"Enter the DHCP netmask (default is {config.get('default_netmask', '255.255.255.0')}): ",
                                    lambda x: x or config.get('default_netmask', '255.255.255.0'))

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
                input("Press Enter to return to the main menu...")
                os.system("clear")

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
                show_about()

            elif choice == "7":
                print(Fore.CYAN + "\nExiting WiFi Extender Tool.")
                break

    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting WiFi Extender Tool due to user interruption...\n")
        logging.warning("Script interrupted by user.")
        try:
            undo_changes = input("Do you want to undo changes made by the script? Y/N: ")
            if undo_changes == "Y":
                revert_changes()
            else:
                sys.exit(0)
        except KeyboardInterrupt:
            print(Fore.RED + "\n\nExiting WiFi Extender Tool due to user interruption...\n")
            sys.exit(0)

    except Exception as e:
        print(Fore.RED + f"\nAn unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        revert_changes()
        sys.exit(1)

def show_about():
    """Display information about the tool."""
    os.system("clear")
    print_banner("About")
    print(Fore.LIGHTCYAN_EX + "\nWi-Fi Extender Tool Pro v1.0")
    print(Fore.LIGHTCYAN_EX + "\nDeveloped by: l1qu1c1ty")
    print(Fore.LIGHTCYAN_EX + "\nDescription: This tool helps you to set up your Raspberry Pi as a WiFi extender with ease.")
    print(Fore.LIGHTCYAN_EX + "\nFeatures:")
    print(Fore.LIGHTCYAN_EX + " - Setup WiFi Extender")
    print(Fore.LIGHTCYAN_EX + " - Revert Changes")
    print(Fore.LIGHTCYAN_EX + " - Check Status")
    print(Fore.LIGHTCYAN_EX + " - Make Configuration Persistent")
    print(Fore.LIGHTCYAN_EX + " - Restart Services")
    print(Fore.LIGHTCYAN_EX + "\nThank you for using this tool!\n")
    print(Fore.RED + '''\nThere is always a risk that you may not be able to boot your Raspberry Pi. 
We are not responsible for what happens, work with the script. Don't blame us.''')
    input(Fore.LIGHTCYAN_EX + "\nPress Enter to return to the main menu...")
    os.system("clear")

if __name__ == "__main__":
    if os.geteuid() != 0:
         print_banner("Error!")
         print(Fore.RED + "This script must be run as root.")
         sys.exit(1)
    else:
        main()
=======
#!/usr/bin/python3
import subprocess
import os
import sys
import logging
from colorama import init, Fore
from pyfiglet import Figlet
import shutil
import yaml
import argparse
import shlex

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='wifi_extender.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom figlet font
custom_fig = Figlet(font='slant')

config = {}

def load_config():
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


def run_command(command, timeout=15):
    """Run a shell command with a timeout."""
    try:
        result = subprocess.run(shlex.split(f"sudo {command}"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        result.check_returncode()
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr}")
        raise RuntimeError(f"Command '{command}' failed with error: {e.stderr}")
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out after {timeout} seconds")
        raise RuntimeError(f"Command '{command}' timed out after {timeout} seconds")
    except Exception as e:
        logging.error(f"Error running command '{command}': {e}")
        raise RuntimeError(f"Error running command '{command}': {e}")


def update_system():
    logging.info("Updating system packages...")
    print(Fore.GREEN + "\n\nUpdating system packages...")
    run_command("apt-get update")
    run_command("apt-get full-upgrade -y")

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
        # Use echo and sudo to write the content
        command = f"echo {shlex.quote(hostapd_conf_content)} | sudo tee {hostapd_conf_path}"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        print(Fore.GREEN + f"Successfully wrote to {hostapd_conf_path}")

        # Set correct permissions for the file
        subprocess.run(f"sudo chmod 600 {hostapd_conf_path}", shell=True, check=True)
        subprocess.run(f"sudo chown root:root {hostapd_conf_path}", shell=True, check=True)

    except subprocess.CalledProcessError as e:
        logging.error(f"Error writing or configuring hostapd.conf: {e}")
        print(Fore.RED + f"Error: {e}")
        raise

def configure_hostapd():
    """Configure and enable hostapd service."""
    logging.info("Configuring hostapd...")
    print(Fore.GREEN + "Configuring hostapd...")

    if not os.path.isfile("/etc/hostapd/hostapd.conf"):
        raise RuntimeError("hostapd configuration file not found. Please run write_hostapd_conf first.")

    try:
        subprocess.run("sudo systemctl unmask hostapd", shell=True, check=True)
        subprocess.run("sudo systemctl enable hostapd", shell=True, check=True)
        print(Fore.GREEN + "Successfully configured hostapd")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error configuring hostapd: {e}")
        print(Fore.RED + f"Error: {e}")
        raise

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
        # Use echo and sudo to write the content
        command = f"echo '{dnsmasq_conf_content}' | sudo tee {dnsmasq_conf_path}"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        print(Fore.GREEN + f"Successfully wrote to {dnsmasq_conf_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error writing dnsmasq.conf: {e}")
        print(Fore.RED + f"Error: {e}")
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
    print(Fore.RESET)
    print(Fore.RED + "="*155)
    print(Fore.YELLOW + run_command("sudo systemctl status hostapd"))
    print(Fore.RED + "="*155)
    print(Fore.LIGHTGREEN_EX + run_command("sudo systemctl status dnsmasq"))
    print(Fore.RED + "="*155)
    print(Fore.CYAN + run_command("sudo systemctl status dhcpcd"))
    print(Fore.RED + "="*155)
    input(Fore.GREEN + "\nPress Enter to return to the main menu...")
    os.system("clear")


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

def parse_arguments():
    parser = argparse.ArgumentParser(description='Raspberry Pi WiFi Extender Setup')
    parser.add_argument('--setup', action='store_true', help='Run full setup')
    parser.add_argument('--revert', action='store_true', help='Revert changes')
    parser.add_argument('--status', action='store_true', help='Check status')
    parser.add_argument('--persist', action='store_true', help='Make configuration persistent')
    parser.add_argument('--restart', action='store_true', help='Restart services')
    parser.add_argument('--ssid', type=str, help='SSID for the hotspot')
    parser.add_argument('--passphrase', type=str, help='Passphrase for the hotspot')
    parser.add_argument('--interface', type=str, help='Network interface for the hotspot')
    parser.add_argument('--ip', type=str, help='IP address for the hotspot')
    return parser.parse_args()

def install_system_package(package):
    """Install a system package using apt-get."""
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', package], check=True)
        print(Fore.GREEN + f"{package} has been installed successfully.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"Failed to install {package}.")

def install_python_package(package):
    """Install a Python package using apt-get."""
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', f'python3-{package}'], check=True)
        print(Fore.GREEN + f"{package} has been installed successfully.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"Failed to install {package}.")

def check_system_package(package):
    """Check if a system package is installed."""
    try:
        subprocess.run(['dpkg', '-s', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_python_package(package):
    """Check if a Python package is installed."""
    try:
        subprocess.run(['python3', '-c', f'import {package}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_dependencies():
    print("Wi-Fi Extender Tool Pro Checking Depencies...")
    """Check if required packages are installed."""
    system_packages = ['hostapd', 'dnsmasq', 'dhcpcd', 'iptables']
    python_packages = ['colorama', 'pyfiglet', 'yaml']

    print(Fore.CYAN + "Checking system packages:")
    for package in system_packages:
        if check_system_package(package):
            print(Fore.GREEN + f" - {package} is installed.")
        else:
            print(Fore.RED + f" - {package} is missing. Please install it.")

    print(Fore.CYAN + "\nChecking Python packages:")
    for package in python_packages:
        if check_python_package(package):
            print(Fore.GREEN + f" - {package} is installed.")
        else:
            print(Fore.RED + f" - {package} is missing. Please install it.")

    # Check if any packages are missing
    missing_system_packages = [pkg for pkg in system_packages if not check_system_package(pkg)]
    missing_python_packages = [pkg for pkg in python_packages if not check_python_package(pkg)]

    if missing_system_packages or missing_python_packages:
        print(Fore.RED + "\nThe following packages are missing and need to be installed:")
        
        if missing_system_packages:
            print(Fore.RED + "System packages:")
            for package in missing_system_packages:
                print(Fore.RED + f" - {package}")

        if missing_python_packages:
            print(Fore.RED + "Python packages:")
            for package in missing_python_packages:
                print(Fore.RED + f" - {package}")

        user_input = input(Fore.YELLOW + "\nDo you want to install the missing packages now? (y/n): ").strip().lower()
        if user_input == 'y':
            for package in missing_system_packages:
                install_system_package(package)
            for package in missing_python_packages:
                install_python_package(package)
            print(Fore.GREEN + "All missing packages have been installed. Please run the script again.")
        else:
            print(Fore.RED + "Please install the missing packages and run the script again.")
        sys.exit(1)

def main():
    global config
    config = load_config()
    args = parse_arguments()

    if args.setup:
        ssid = args.ssid or get_valid_input("Enter the SSID for your hotspot: ", validate_ssid)
        passphrase = args.passphrase or get_valid_input("Enter the passphrase for your hotspot: ", validate_passphrase)
        interface = args.interface or get_valid_input(
            f"Enter the network interface for your hotspot (default is {config.get('default_interface', 'wlan1')}): ",
            lambda x: x or config.get('default_interface', 'wlan1')
        )
        ip_address = args.ip or get_valid_input(
            f"Enter the IP address for your hotspot (default is {config.get('default_ip_address', '192.168.2.1/24')}): ",
            lambda x: x or config.get('default_ip_address', '192.168.2.1/24')
        )

        try:
            update_system()
            install_packages()
            write_hostapd_conf(ssid, passphrase, interface)
            configure_hostapd()
            write_dnsmasq_conf()
            configure_dhcpcd(interface, ip_address)
            enable_ip_forwarding()
            configure_iptables()
            start_services()
            print(Fore.GREEN + "\nHotspot setup is complete. Your Raspberry Pi is now a WiFi extender.")
            input("Press Enter to return to the main menu...")
            logging.info("WiFi extender setup completed successfully.")
        except Exception as e:
            logging.error(f"Setup failed: {e}")
            print(Fore.RED + f"Setup failed: {e}")

    elif args.revert:
        try:
            revert_changes()
            print(Fore.YELLOW + "\nReverted changes. WiFi extender setup undone.")
            logging.info("Changes reverted successfully.")
        except Exception as e:
            logging.error(f"Revert failed: {e}")
            print(Fore.RED + f"Revert failed: {e}")

    elif args.status:
        show_status()

    elif args.persist:
        try:
            persist_configuration()
            print(Fore.GREEN + "\nConfiguration is now persistent.")
        except Exception as e:
            logging.error(f"Persisting configuration failed: {e}")
            print(Fore.RED + f"Persisting configuration failed: {e}")

    elif args.restart:
        try:
            restart_services()
            print(Fore.GREEN + "\nServices have been restarted.")
            logging.info("Services restarted successfully.")
        except Exception as e:
            logging.error(f"Restarting services failed: {e}")
            print(Fore.RED + f"Restarting services failed: {e}")

    else:
        # If no arguments are provided, run the interactive menu
        interactive_menu()

def interactive_menu():
    os.system("clear")
    """Main function to run the WiFi extender setup."""
    try:
        # Check dependencies
        check_dependencies()
        input(Fore.YELLOW + "\nPress enter to continue...")
        os.system("clear")
        while True:
            print_banner("Wi-Fi Extender Tool Pro")
            print(Fore.LIGHTGREEN_EX + "\nMenu Options:")
            print(Fore.YELLOW + "\n1. Setup WiFi Extender")
            print(Fore.YELLOW + "2. Revert Changes")
            print(Fore.YELLOW + "3. Check Status")
            print(Fore.YELLOW + "4. Make Configuration Persistent")
            print(Fore.YELLOW + "5. Restart Services")
            print(Fore.YELLOW + "6. About")
            print(Fore.YELLOW + "7. Exit\n")

            choice = get_valid_input(Fore.LIGHTGREEN_EX +"Enter your choice [1,2,3,4,5,6,7]: ",
                                        lambda x: x.isdigit() and int(x) in [1, 2, 3, 4, 5, 6, 7])

            if choice == "1":
                ssid = get_valid_input("Enter the SSID for your hotspot: ", validate_ssid)
                passphrase = get_valid_input("Enter the passphrase for your hotspot: ", validate_passphrase)
                interface = get_valid_input(f"Enter the network interface for your hotspot (default is {config.get('default_interface', 'wlan1')}): ",
                                    lambda x: x or config.get('default_interface', 'wlan1'))
                ip_address = get_valid_input(f"Enter the IP address for your hotspot (default is {config.get('default_ip_address', '192.168.2.1/24')}): ",
                                    lambda x: x or config.get('default_ip_address', '192.168.2.1/24'))
                dhcp_start = get_valid_input(f"Enter the DHCP range start (default is {config.get('default_dhcp_start', '192.168.2.2')}): ",
                                    lambda x: x or config.get('default_dhcp_start', '192.168.2.2'))
                dhcp_end = get_valid_input(f"Enter the DHCP range end (default is {config.get('default_dhcp_end', '192.168.2.255')}): ",
                                    lambda x: x or config.get('default_dhcp_end', '192.168.2.255'))
                netmask = get_valid_input(f"Enter the DHCP netmask (default is {config.get('default_netmask', '255.255.255.0')}): ",
                                    lambda x: x or config.get('default_netmask', '255.255.255.0'))

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
                show_about()

            elif choice == "7":
                print(Fore.CYAN + "\nExiting WiFi Extender Tool.")
                break

    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting WiFi Extender Tool due to user interruption...\n")
        logging.warning("Script interrupted by user.")
        try:
            undo_changes = input("Do you want to undo changes made by the script? Y/N: ")
            if undo_changes == "Y":
                revert_changes()
            else:
                sys.exit(0)
        except KeyboardInterrupt:
            print(Fore.RED + "\n\nExiting WiFi Extender Tool due to user interruption...\n")
            sys.exit(0)

    except Exception as e:
        print(Fore.RED + f"\nAn unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        revert_changes()
        sys.exit(1)

def show_about():
    """Display information about the tool."""
    os.system("clear")
    print_banner("About")
    print(Fore.LIGHTCYAN_EX + "\nWi-Fi Extender Tool Pro v1.0")
    print(Fore.LIGHTCYAN_EX + "\nDeveloped by: l1qu1c1ty")
    print(Fore.LIGHTCYAN_EX + "\nDescription: This tool helps you to set up your Raspberry Pi as a WiFi extender with ease.")
    print(Fore.LIGHTCYAN_EX + "\nFeatures:")
    print(Fore.LIGHTCYAN_EX + " - Setup WiFi Extender")
    print(Fore.LIGHTCYAN_EX + " - Revert Changes")
    print(Fore.LIGHTCYAN_EX + " - Check Status")
    print(Fore.LIGHTCYAN_EX + " - Make Configuration Persistent")
    print(Fore.LIGHTCYAN_EX + " - Restart Services")
    print(Fore.LIGHTCYAN_EX + "\nThank you for using this tool!\n")
    print(Fore.RED + '''\nThere is always a risk that you may not be able to boot your Raspberry Pi. 
We are not responsible for what happens, work with the script. Don't blame us.''')
    input(Fore.LIGHTCYAN_EX + "\nPress Enter to return to the main menu...")
    os.system("clear")

if __name__ == "__main__":
    if os.geteuid() != 0:
         print_banner("Error!")
         print(Fore.RED + "This script must be run as root.")
         sys.exit(1)
    else:
        main()
>>>>>>> 105142bf438cc4e4a8ff9bfd8635d6b91c51ec7d

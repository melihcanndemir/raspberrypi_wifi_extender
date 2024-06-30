import os
import subprocess

def check_and_create_hostapd_conf():
    hostapd_conf_content = """
interface=wlan0
driver=nl80211
ssid=YourSSID
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=YourPassphrase
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    hostapd_conf_path = "/etc/hostapd/hostapd.conf"
    
    # Check if the hostapd.conf file exists
    if not os.path.exists(hostapd_conf_path):
        # Create the hostapd.conf file
        with open(hostapd_conf_path, "w") as f:
            f.write(hostapd_conf_content)
        print(f"Created {hostapd_conf_path} with default configuration.")
    else:
        print(f"{hostapd_conf_path} already exists.")

def check_and_create_default_hostapd():
    default_hostapd_content = """
# Defaults for hostapd initscript
#
# See /usr/share/doc/hostapd/README.Debian for information about alternative
# methods of managing hostapd.

DAEMON_CONF="/etc/hostapd/hostapd.conf"
"""
    default_hostapd_path = "/etc/default/hostapd"
    
    # Check if the /etc/default/hostapd file exists
    if os.path.exists(default_hostapd_path):
        with open(default_hostapd_path, "r") as f:
            content = f.read()
        
        # Check if DAEMON_CONF is correctly set
        if 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' not in content:
            # Correct the DAEMON_CONF setting
            with open(default_hostapd_path, "w") as f:
                f.write(default_hostapd_content)
            print(f"Updated {default_hostapd_path} with correct DAEMON_CONF.")
        else:
            print(f"{default_hostapd_path} already has correct DAEMON_CONF.")
    else:
        # Create the /etc/default/hostapd file
        with open(default_hostapd_path, "w") as f:
            f.write(default_hostapd_content)
        print(f"Created {default_hostapd_path} with default configuration.")

def restart_hostapd_service():
    try:
        subprocess.run(["sudo", "systemctl", "restart", "hostapd"], check=True)
        print("hostapd service restarted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to restart hostapd service: {e}")

def main():
    check_and_create_hostapd_conf()
    check_and_create_default_hostapd()
    restart_hostapd_service()

if __name__ == "__main__":
    main()
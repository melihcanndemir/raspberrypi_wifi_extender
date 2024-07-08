Raspberry Pi WiFi Extender Tool

This Python script helps you configure a Raspberry Pi as a WiFi extender, allowing devices to connect to your existing WiFi network through the Raspberry Pi.

Features:

Creates a WiFi hotspot with a user-defined SSID and passphrase.
Assigns IP addresses to connected devices using DHCP.
Enables internet access for devices connected to the extender.
Provides a user-friendly menu for configuration and management.
Offers options to revert changes and check service status.
Requirements:

Raspberry Pi running a Debian-based operating system (e.g., Raspberry Pi OS).
Root privileges to execute the script.
WiFi adapter connected to the Raspberry Pi.
hostapd and dnsmasq packages installed (script can install them for you).
Installation:

Clone or download the script repository.
Open a terminal and navigate to the script directory.
Run the script with root privileges:
Bash
sudo python3 wifi_extender_tool3.py

Usage:

The script presents a menu with the following options:

Setup WiFi Extender: Configure the extender with your desired settings.
Revert Changes: Undo any modifications made by the script.
Check Status: View the status of relevant services.
Make Configuration Persistent (Optional): Add a script execution line to /etc/rc.local to automatically set up the extender on boot.
Restart Services: Restart services involved in the WiFi extender functionality.
Exit: Quit the script.
Follow the on-screen prompts to enter the necessary details for your WiFi network and configuration.

Notes:

The script prompts for the WiFi password. Consider using environment variables or a separate configuration file for improved security in real-world deployments.
Ensure your Raspberry Pi's WiFi adapter is configured to connect to your existing WiFi network before running the script.

Additional Information:

Refer to the script source code (wifi_extender_tool3.py) for detailed function definitions and implementation.
# raspberrypi wifi extender

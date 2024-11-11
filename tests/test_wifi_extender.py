# tests/test_wifi_extender.py

import pytest
from wifi_extender_tool3 import validate_ssid, validate_passphrase, run_command
from wifi_extender_tool3 import install_packages, write_hostapd_conf, configure_hostapd
from unittest.mock import patch, MagicMock
import tempfile
import os


def test_validate_ssid_valid():
    assert validate_ssid("MySSID") == True

def test_validate_ssid_too_long():
    assert validate_ssid("ThisIsAVeryLongSSIDThatExceedsTheMaximumLengthAllowed") == False

def test_validate_passphrase_valid():
    assert validate_passphrase("StrongPassphrase123") == True

def test_validate_passphrase_too_short():
    assert validate_passphrase("Short1") == False

def test_run_command_success():
    result = run_command("ls -l")
    assert "total" in result

def test_run_command_failure():
    with pytest.raises(RuntimeError):
        run_command("non_existing_command")

def test_run_command_timeout():
    with pytest.raises(RuntimeError):
        run_command("sleep 5", timeout=3)

def test_install_packages():
    with pytest.raises(RuntimeError):
        install_packages()


@pytest.fixture
def mock_hostapd_conf():
    # Create a temporary file for hostapd.conf
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"")
        temp_file.flush()
        yield temp_file.name
    os.remove(temp_file.name)

def test_write_hostapd_conf(mock_hostapd_conf):
    ssid = "TestSSID"
    passphrase = "TestPassphrase"
    interface = "wlan1"
    channel = 9
    hw_mode = "g"
    ieee80211n = 1
    ieee80211ac = 1

    write_hostapd_conf(ssid, passphrase, interface, channel, hw_mode, ieee80211n, ieee80211ac)
    
    # Check if the content was written correctly to the mocked hostapd.conf file
    with open(mock_hostapd_conf, 'r') as f:
        content = f.read()
        assert f"ssid={ssid}" in content
        assert f"wpa_passphrase={passphrase}" in content
        assert f"interface={interface}" in content
        assert f"channel={channel}" in content
        assert f"hw_mode={hw_mode}" in content
        assert f"ieee80211n={ieee80211n}" in content
        assert f"ieee80211ac={ieee80211ac}" in content

@patch('wifi_extender_tool3.run_command')
def test_configure_hostapd(mock_run_command):
    mock_run_command.side_effect = lambda cmd: MagicMock(returncode=0)
    with patch('os.path.isfile', return_value=True):
        configure_hostapd()
    
    # Check if systemctl commands were called correctly
    mock_run_command.assert_any_call("sudo systemctl unmask hostapd")
    mock_run_command.assert_any_call("sudo systemctl enable hostapd")
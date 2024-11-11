from flask import Flask, render_template, request, redirect
import paramiko
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

status = {
    'connected_clients': 0,
    'signal_strength': None,
    'ssid': None,
    'channel': None,
    'security_protocol': None,
    'interface': None
}

def read_credentials():
    try:
        with open("credentials.txt", "r") as f:
            username = f.readline().strip()
            password = f.readline().strip()
        return username, password
    except FileNotFoundError:
        logging.error("Error: credentials.txt file not found!")
        return None, None

ssh_host = '192.168.1.84'
ssh_port = 22

def create_ssh_client():
    try:
        username, password = read_credentials()
        if not username or not password:
            return None
        
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ssh_host, port=ssh_port, username=username, password=password)
        return ssh_client
    except Exception as e:
        logging.error(f'SSH bağlantısı kurulamadı: {str(e)}')
        return None

def get_extender_status():
    try:
        global status
        ssh_client = create_ssh_client()
        if not ssh_client:
            logging.error("SSH bağlantısı kurulamadı")
            return

        logging.debug("SSH bağlantısı başarılı, komutları çalıştırıyorum...")

        # SSID ve Kanal
        stdin, stdout, stderr = ssh_client.exec_command('bash -c "sudo iw dev wlan1 info"')
        output = stdout.read().decode()
        error = stderr.read().decode()
        logging.debug(f"iw dev wlan1 info çıktısı:\n{output}")
        if error:
            logging.error(f"iw dev wlan1 info hatası: {error}")

        for line in output.splitlines():
            if 'ssid' in line.lower():
                status['ssid'] = line.split()[-1].strip()
            if 'channel' in line.lower():
                status['channel'] = line.split()[1].strip()
        logging.debug(f"SSID: {status['ssid']}, Kanal: {status['channel']}")

        # Güvenlik protokolü
        stdin, stdout, stderr = ssh_client.exec_command('bash -c "sudo cat /etc/hostapd/hostapd.conf"')
        output = stdout.read().decode()
        error = stderr.read().decode()
        logging.debug(f"hostapd.conf içeriği:\n{output}")
        if error:
          logging.error(f"hostapd.conf okuma hatası: {error}")

        for line in output.splitlines():
            if 'wpa_key_mgmt' in line.lower():
                key_mgmt = line.split('=')[1].strip()
                if 'WPA-PSK' in key_mgmt:
                    status['security_protocol'] = 'WPA2'
                elif 'WPA2-PSK' in key_mgmt:
                    status['security_protocol'] = 'WPA3'
                else:
                    status['security_protocol'] = 'Diğer'
        logging.debug(f"Güvenlik Protokolü: {status['security_protocol']}")

        # Arayüz
        stdin, stdout, stderr = ssh_client.exec_command('bash -c "sudo iwconfig | grep Mode:Master"')
        output = stdout.read().decode()
        error = stderr.read().decode()
        logging.debug(f"iwconfig çıktısı:\n{output}")
        if error:
            logging.error(f"iwconfig hatası: {error}")

        for line in output.splitlines():
            if 'wlan' in line:
                status['interface'] = line.split()[0]
                break  # İlk wlan arayüzünü aldıktan sonra döngüyü sonlandır

        logging.debug(f"Arayüz: {status['interface']}")

        # Bağlı istemciler
        stdin, stdout, stderr = ssh_client.exec_command('bash -c "sudo /usr/sbin/iw dev wlan1 station dump"')
        output = stdout.read().decode()
        error = stderr.read().decode()
        logging.debug(f"iw dev wlan1 station dump çıktısı:\n{output}")
        if error:
            logging.error(f"iw dev wlan1 station dump hatası: {error}")

        connected_clients = []
        for line in output.splitlines():
            if 'Station' in line:
                mac_address = line.split()[1]
                connected_clients.append(mac_address)
        status['connected_clients'] = len(connected_clients)
        logging.debug(f"Bağlı istemciler: {connected_clients}")

        # Sinyal gücü
        if connected_clients:
            signal_strengths = []
            iw_path = "/usr/sbin/iw"
            for client in connected_clients:
                stdin, stdout, stderr = ssh_client.exec_command(f'bash -c "sudo {iw_path} dev wlan1 station get {client}"')
                output = stdout.read().decode()
                for line in output.splitlines():
                    if 'signal:' in line.lower():
                        signal_strengths.append(int(line.split(':')[1].strip().split()[0]))
            if signal_strengths:
                status['signal_strength'] = sum(signal_strengths) / len(signal_strengths)
            else:
                status['signal_strength'] = None
            logging.debug(f"Sinyal Gücü: {status['signal_strength']}")
        else:
            status['signal_strength'] = None
            logging.debug("Bağlı istemci olmadığı için sinyal gücü hesaplanamadı.")

        ssh_client.close()
    except Exception as e:
        logging.error(f'Hata oluştu: {str(e)}')
        raise

def get_network_info(ssh_client):
    try:
        stdin, stdout, stderr = ssh_client.exec_command('bash -c "sudo ip addr show wlan1"')
        output = stdout.read().decode()
        error = stderr.read().decode()
        logging.debug(f"ip addr show çıktısı:\n{output}")
        if error:
            logging.error(f"ip addr show hatası: {error}")

        ip_info = {}
        for line in output.splitlines():
            if 'inet ' in line:
                parts = line.split()
                ip_info['ip_address'] = parts[1]
                ip_info['netmask'] = parts[3]
            elif 'inet6 ' in line:
                parts = line.split()
                ip_info['ipv6_address'] = parts[1]
        
        logging.debug(f"IP Adresi: {ip_info.get('ip_address')}, Alt Ağ Maskesi: {ip_info.get('netmask')}")
        return ip_info
    except Exception as e:
        logging.error(f'Hata oluştu: {str(e)}')
        return None


def get_current_config(ssh_client):
    try:
        stdin, stdout, stderr = ssh_client.exec_command('cat /etc/hostapd/hostapd.conf')
        current_config = {}
        for line in stdout:
            if '=' in line:
                key, value = line.strip().split('=')
                current_config[key.strip()] = value.strip()
        return current_config
    except Exception as e:
        logging.error(f'Hata oluştu: {str(e)}')
        return None

def update_extender_config(ssh_client, new_config):
    try:
        with ssh_client.open_sftp() as sftp:
            with sftp.file('/etc/hostapd/hostapd.conf', 'w') as f:
                for key, value in new_config.items():
                    f.write(f'{key}={value}\n')
        logging.info('Konfigürasyon başarıyla güncellendi.')
    except Exception as e:
        logging.error(f'Hata oluştu: {str(e)}')

@app.route('/')
def index():
    error_message = None
    try:
        ssh_client = create_ssh_client()
        if ssh_client:
            logging.info("SSH bağlantısı başarılı")
            ssh_client.close()
            get_extender_status()
        else:
            error_message = "SSH bağlantısı kurulamadı"
    except Exception as e:
        error_message = str(e)
    return render_template('index.html', status=status, error=error_message)

@app.route('/configure', methods=['GET', 'POST'])
def configure():
    ssh_client = create_ssh_client()
    if not ssh_client:
        return "SSH bağlantısı kurulamadı!", 500

    if request.method == 'GET':
        current_config = get_current_config(ssh_client)
        ssh_client.close()
        return render_template('configure.html', config=current_config)
    elif request.method == 'POST':
        new_config = request.form.to_dict()
        update_extender_config(ssh_client, new_config)
        ssh_client.close()
        return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

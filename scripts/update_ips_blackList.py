import paramiko
import requests
import os
import json

# Leer el archivo de configuración
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

router_ip = config['router_ip']
router_port = config['router_port']
router_user = config['router_user']
router_password = config['router_password']

# URL del archivo de direcciones IP
file_url = "https://github.com/playa-senator/ip-block-forti/raw/main/ip-address-of-attackers.txt"

# Nombre del archivo temporal para guardar la salida del comando
temp_file_name = "temp_firewall_address_list.txt"

try:
    # Crear una conexión SSH
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(router_ip, port=router_port, username=router_user, password=router_password, look_for_keys=False)

    # Ejecutar el comando SSH para obtener las direcciones IP existentes en la lista
    command = "/ip firewall address-list print where list=blacklist_IPs"
    stdin, stdout, stderr = ssh_client.exec_command(command)

    # Filtrar la salida para obtener las direcciones IP
    existing_ips = {line.split()[2] for line in stdout if "blacklist_IPs" in line}

    # Descargar las direcciones IP desde la URL
    response = requests.get(file_url)
    remote_ips = set(response.text.strip().splitlines())

    # Determinar las direcciones IP que deben agregarse al enrutador MikroTik
    ips_to_add = remote_ips - existing_ips

    # Agregar las direcciones IP faltantes al enrutador MikroTik
    for ip in ips_to_add:
        if ip:
            command = f"/ip firewall address-list add list=blacklist_IPs address={ip}"
            stdin, stdout, stderr = ssh_client.exec_command(command)
            error_output = stderr.read().decode("utf-8")
            if not error_output:
                print(f"Agregada dirección IP: {ip}")
            else:
                print(f"Error al agregar dirección IP: {ip}")

    # Cerrar la conexión SSH
    ssh_client.close()

    print("Actualización de IPs Bloqueadas completada en el  MikroTik.")

except Exception as e:
    print(f"Error: {str(e)}")

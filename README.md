# Guía Básica

## Actualizar IPs Maliciosas
Con la ayuda de este script descargas un archivo temporal de Github donde solamente hay IPs maliciosas en texto plano, y comparas con las IPs que tiene la lista con el nombre **blacklist_IPs** y las que no estén se añaden. Además te aparece por consola las IPs que añade.
También por seguridad hay un archivo json donde debes añadir información para el login hacia el Mikrotik.

``` python
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
    ssh_client.connect(router_ip, port=router_port, username=router_user, password=router_password)

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
    print("Actualización de IPs Bloqueadas completada en el  MikroTik.")
  
except Exception as e:

    print(f"Error: {str(e)}")
```

## Limitar Ancho de Banda a Webs

Este tipo de script se puede adaptar para limitar o bloquear el ancho de banda de cualquier servicio o dominio específico en una red. Al modificar los criterios de marcado en las reglas de firewall, se pueden identificar diferentes servicios o dominios. 

Por ejemplo, cambiando las cadenas de texto en las reglas de marcado de conexiones y paquetes, se puede apuntar hacia cualquier servicio, plataforma o dominio en particular. 

Posteriormente, al utilizar el módulo de colas ("queue") con diferentes límites de velocidad, es posible aplicar restricciones similares a otros servicios o sitios web según sea necesario para administrar el ancho de banda disponible en la red.

La parte que hay que modificar es: ***tls-host=*tiktok****

``` bash
/ip firewall mangle
## Dominio que se quiere bloquear
add action=mark-connection chain=prerouting comment=\
    "Marcar conexiones TikTok" new-connection-mark=Tiktok-Connection \
    passthrough=yes protocol=tcp tls-host=*tiktok*
add action=mark-connection chain=prerouting new-connection-mark=\
    Tiktok-Connection passthrough=yes protocol=tcp tls-host=*tiktok.com
    
##Marcar paquetes
add action=mark-packet chain=prerouting comment=\
    "Marcar TODOS los paquetes TikTok" connection-mark=Tiktok-Connection \
    new-packet-mark=Tiktok-Packet passthrough=no

/queue simple
##Límite que se quiere poner
add comment=\
    "Internet Package (Upload Speed: 10 Mbps, Download Speed: 10 Mbps)" \
    max-limit=10M/10M name=Tiktok packet-marks=Tiktok-Packet target=\
    10.12.100.0/24
```

## Reglas Básicas
### Address Lists
#### "Local LAN":

Define una lista de direcciones IP locales (10.12.0.0/24) para permitir el acceso a servicios internos. Esta lista se utiliza para identificar tráfico interno que no debería ser bloqueado por las reglas de acceso.

#### "bogons":

Agrupa direcciones IP reservadas o no utilizables según estándares (0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 192.0.2.0/24, 192.88.99.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4). Estas direcciones suelen ser reservadas para usos especiales o son direcciones no asignables en internet.

``` bash
/ip firewall address-list
add address=10.12.0.0/24 list="Local LAN"
add address=0.0.0.0/8 comment="Self-Identification [RFC 3330]" list=bogons
add address=127.0.0.0/8 comment="Loopback [RFC 3330]" list=bogons
add address=169.254.0.0/16 comment="Link Local [RFC 3330]" list=bogons
add address=192.0.2.0/24 comment="Reserved - IANA - TestNet1" list=bogons
add address=192.88.99.0/24 comment="6to4 Relay Anycast [RFC 3068]" list=\
    bogons
add address=198.18.0.0/15 comment="NIDB Testing" list=bogons
add address=198.51.100.0/24 comment="Reserved - IANA - TestNet2" list=bogons
add address=203.0.113.0/24 comment="Reserved - IANA - TestNet3" list=bogons
add address=224.0.0.0/4 comment=\
    "MC, Class D, IANA # Check if you need this subnet before enable it" \
    list=bogons
```

## Firewall Rules:

#### Control de Acceso SSH:

Esta regla bloquea el acceso SSH al puerto 22244, excepto para direcciones IP que estén en la lista "Local LAN". Registra intentos de acceso rechazados.

``` bash
/ip firewall filter
add action=drop chain=input comment="ACCESO SSH - menos la lista Local LAN #" \
    dst-port=222442 log=yes protocol=tcp src-address-list="!Local LAN"
```

### Bloqueo de Denegación de Servicio (DoS) y escaneos de puertos:
Esta regla identifica intentos de Denegación de Servicio (DoS) mediante la limitación de conexiones TCP con la bandera SYN y agrega las direcciones IP a la lista "Syn_Flooder" durante 30 minutos.
``` bash
add action=add-src-to-address-list address-list=Syn_Flooder \
    address-list-timeout=30m chain=input comment=\
    "Anade a la list Syn_Flooder (Intentos DoS)" connection-limit=30,32 \
    protocol=tcp tcp-flags=syn
add action=drop chain=input comment="Drop Intento de DoS de la lista" \
    src-address-list=Syn_Flooder
``` 


Esta regla identifica intentos de escaneo de puertos TCP según un patrón de firma y agrega las direcciones IP a la lista "Port_Scanner" durante 1 semana.

``` bash
add action=add-src-to-address-list address-list=Port_Scanner \
    address-list-timeout=1w chain=input comment="Port Scanner Detect" \
    protocol=tcp psd=21,3s,3,1
add action=drop chain=input comment="Drop to port scan list" \
    src-address-list=Port_Scanner
```

#### Control Tráfico Spammers

Estas reglas identifican las direcciones IP sospechosas y las incluyen en una lista temporal. Limitan la conexión SMTP a 30 intentos por minuto. Posteriormente, todo el tráfico procedente de estas direcciones IP hacia el puerto SMTP (25,587) se descarta para prevenir actividad no deseada

``` bash
add action=add-src-to-address-list address-list=spammers address-list-timeout=3h chain=forward comment="Añade spammers a una lista y no hay más tráfico de correo - durante 3h" connection-limit=30,32 dst-port=25,587 limit=30/1m,0:packet protocol=tcp

add action=drop chain=forward comment="Drop de Spammers" dst-port=25,587 protocol=tcp src-address-list=spammers

```

#### Bloqueo de Todo:

Establece una regla predeterminada que bloquea todo el tráfico entrante en la interfaz ether1. 

Esta regla sirve como medida de seguridad para bloquear todo el tráfico no autorizado o no gestionado, **debe estar al final del todo**.

``` bash
add action=drop chain=input comment="BLOQUEO DE TODO" in-interface=ether1
```


# -*- coding: utf-8 -*-

import subprocess
import re
import os
import sys
from datetime import datetime

def verificar_nmap():
    """
    Verifica si Nmap está instalado en el sistema.
    Si no lo está, termina la ejecución del script.
    """
    try:
        # Ejecuta 'nmap -V' para verificar la instalación.
        # Se redirige la salida para no mostrarla en la consola.
        subprocess.run(['nmap', '-V'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Nmap está instalado. Continuando con el script.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Si el comando falla o no se encuentra, Nmap no está instalado.
        print("[!] Error: Nmap no está instalado o no se encuentra en el PATH del sistema.")
        print("    Por favor, instálalo para poder ejecutar este script.")
        print("    Puedes descargarlo desde: https://nmap.org/download.html")
        sys.exit(1) # Termina el script con un código de error.

def descubrir_hosts_activos(red_cidr):
    """
    Descubre hosts activos en la red usando un ping scan.
    
    Args:
        red_cidr (str): La red en formato CIDR (ej. "192.168.1.0/24").

    Returns:
        list: Una lista de direcciones IP de los hosts activos.
    """
    print(f"\n--- BUSCANDO HOSTS ACTIVOS en {red_cidr} ---")
    hosts_activos = []
    try:
        # Usamos nmap con la opción -sn (Ping Scan) que deshabilita el escaneo de puertos.
        comando = ['nmap', '-sn', '-Pn', red_cidr]
        print(f"[*] Ejecutando comando: {' '.join(comando)}")
        
        resultado = subprocess.check_output(comando, universal_newlines=True)
        
        # Usamos una expresión regular para encontrar todas las IPs en el resultado.
        hosts_activos = re.findall(r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", resultado)
        
        if hosts_activos:
            print(f"[+] Hosts activos encontrados: {len(hosts_activos)}")
            for host in hosts_activos:
                print(f"    - {host}")
        else:
            print("[!] No se encontraron hosts activos en la red.")
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al ejecutar nmap para descubrir hosts: {e}")
    except FileNotFoundError:
        print("[!] Error: El comando 'nmap' no fue encontrado.")
        
    return hosts_activos

def escanear_puertos_abiertos(ip):
    """
    ETAPA 1: Escanea una IP para encontrar solo los puertos abiertos.
    
    Args:
        ip (str): La dirección IP a escanear.

    Returns:
        list: Una lista de números de puerto (como strings) que están abiertos.
    """
    print(f"\n--- ETAPA 1: Buscando puertos abiertos en {ip} ---")
    puertos_abiertos = []
    try:
        # -p- escanea todos los puertos.
        # --open muestra solo los puertos en estado 'open'.
        # -T4 acelera el escaneo.
        comando = ['nmap', '-p-', '--open', '-Pn', '-n', ip]
        print(f"[*] Ejecutando comando: {' '.join(comando)}")
        
        resultado = subprocess.check_output(comando, universal_newlines=True, stderr=subprocess.PIPE)
        
        # Expresión regular para encontrar líneas como "80/tcp open http" y extraer el número de puerto.
        puertos_abiertos = re.findall(r'(\d+)/tcp\s+open', resultado)
        
        if puertos_abiertos:
            print(f"[+] Puertos abiertos encontrados en {ip}: {', '.join(puertos_abiertos)}")
        else:
            print(f"[!] No se encontraron puertos TCP abiertos en {ip}.")

    except subprocess.CalledProcessError as e:
        # Nmap a menudo devuelve un código de error si no encuentra puertos, así que lo manejamos.
        if "0 hosts up" not in e.stdout and "scanned in" in e.stdout:
             print(f"[!] No se encontraron puertos TCP abiertos en {ip}.")
        else:
            print(f"[!] Error al escanear puertos en {ip}: {e.stderr}")
    
    return puertos_abiertos

def escanear_servicios_en_puertos(ip, puertos):
    """
    ETAPA 2: Escanea servicios y scripts en una lista específica de puertos.
    
    Args:
        ip (str): La dirección IP a escanear.
        puertos (list): Lista de puertos a escanear.

    Returns:
        str: El resultado completo del escaneo de Nmap.
    """
    if not puertos:
        return "No hay puertos abiertos para escanear servicios."

    puertos_str = ",".join(puertos)
    print(f"\n--- ETAPA 2: Escaneando servicios en {ip} en los puertos: {puertos_str} ---")
    
    try:
        # -p especifica los puertos.
        # -sCV ejecuta scripts por defecto y detecta versiones de servicios.
        comando = ['nmap', '-p', puertos_str, '--max-rate 200', '-sCV', '-Pn', ip]
        print(f"[*] Ejecutando comando: {' '.join(comando)}")
        
        resultado = subprocess.check_output(comando, universal_newlines=True, stderr=subprocess.PIPE)
        return resultado
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al escanear servicios en la IP {ip}: {e.stderr}")
        return f"Error al escanear servicios en la IP {ip}.\n{e.stderr}"

def guardar_resultados(ip, datos_escaneo, directorio):
    """
    Guarda los resultados del escaneo de una IP en un archivo de texto.
    
    Args:
        ip (str): La dirección IP escaneada.
        datos_escaneo (str): Los resultados del escaneo de Nmap.
        directorio (str): El directorio donde se guardarán los archivos.
    """
    nombre_archivo = f"nmap_{ip.replace('.', '_')}.txt"
    ruta_completa = os.path.join(directorio, nombre_archivo)
    
    try:
        with open(ruta_completa, 'w', encoding='utf-8') as archivo:
            archivo.write(f"Resultados del escaneo para la IP: {ip}\n")
            archivo.write(f"Fecha del escaneo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            archivo.write("="*50 + "\n\n")
            archivo.write(datos_escaneo)
        print(f"[+] Resultados para {ip} guardados en: {ruta_completa}")
    except IOError as e:
        print(f"[!] No se pudo escribir el archivo para {ip}: {e}")

def main():
    """
    Función principal que orquesta todo el proceso de escaneo.
    """
    # --- Configuración ---
    red_a_escanear = "192.168.1.0/24"
    directorio_resultados = ("resultados_escaneo")
    
    print("="*50)
    print("      SCRIPT DE ESCANEO DE RED AUTOMATIZADO (2 ETAPAS)")
    print("="*50)
    
    verificar_nmap()

    hosts_activos = descubrir_hosts_activos(red_a_escanear)
    
    if not hosts_activos:
        print("\n[!] No hay hosts para escanear. Finalizando el script.")
        return

    if not os.path.exists(directorio_resultados):
        print(f"\n[*] Creando directorio para los resultados: '{directorio_resultados}'")
        os.makedirs(directorio_resultados)
        
    print("\n--- INICIANDO ESCANEO DETALLADO Y GUARDADO ---")
    for ip in hosts_activos:
        # Etapa 1: Descubrir puertos abiertos
        puertos_abiertos = escanear_puertos_abiertos(ip)
        
        if puertos_abiertos:
            # Etapa 2: Escanear servicios en esos puertos
            resultado_final = escanear_servicios_en_puertos(ip, puertos_abiertos)
            guardar_resultados(ip, resultado_final, directorio_resultados)
        else:
            # Si no hay puertos, se guarda un archivo indicándolo.
            mensaje_sin_puertos = f"No se encontraron puertos TCP abiertos en la IP: {ip}"
            guardar_resultados(ip, mensaje_sin_puertos, directorio_resultados)

    print("\n[+] Proceso de escaneo y guardado completado.")
    print(f"[*] Todos los reportes se encuentran en la carpeta: '{directorio_resultados}'")
    print("="*50)

if __name__ == "__main__":
    main()

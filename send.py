#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    from scapy.all import getmacbyip
    dst_mac = getmacbyip(addr)
    if not dst_mac:
        print(f"Could not resolve MAC for {addr}, using broadcast")
        dst_mac = 'ff:ff:ff:ff:ff:ff'
    
    print(f"Destination MAC: {dst_mac}")
    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac)
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    print("\nPacket structure:")
    pkt.show2()
    print("\nSending packet...")
    sendp(pkt, iface=iface, verbose=False)
    print("Packet sent!")


if __name__ == '__main__':
    main()

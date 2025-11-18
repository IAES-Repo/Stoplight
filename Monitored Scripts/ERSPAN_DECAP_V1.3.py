"""
ERSPAN Decapsulation Script v1.2
Listens for ERSPAN packets on a specified interface, decapsulates them,
and forwards the inner packets to a VETH device.

Author: Jordan Lanham
Date: 2025-11-18
"""

import os
from scapy.all import *
from scapy.contrib.erspan import ERSPAN_II

INTERFACE = "eno8303"  # Replace with your network interface
OUTPUT_VETH = "SocDecap"  # Replace with your output VETH device name
PEER_VETH = "ChetDecap"  # Peer end of the VETH pair

def create_veth_pair(veth_name, peer_name):
    # Create VETH pair
    os.system(f"ip link add {veth_name} type veth peer name {peer_name}")
    
    # Bring both ends up
    os.system(f"ip link set {veth_name} up")
    os.system(f"ip link set {peer_name} up")
    
    # Configure IP addresses (optional - you can modify as needed)
    os.system(f"ip addr add 192.168.1.1/24 dev {veth_name}")
    os.system(f"ip addr add 192.168.1.2/24 dev {peer_name}")
    
    print(f"VETH pair {veth_name} <-> {peer_name} created and configured.")

def packet_decap(packet):
    if ERSPAN_II in packet:
        inner_packet = packet[ERSPAN_II].payload
        return inner_packet
        
def packet_callback(packet):
    decapped_packet = packet_decap(packet)
    if decapped_packet:
        sendp(decapped_packet, iface=OUTPUT_VETH, verbose=True)
        print(f"Forwarded packet: {decapped_packet.summary()}")
    else:
        print("No ERSPAN layer found, packet ignored.")
        return

def main():
    create_veth_pair(OUTPUT_VETH, PEER_VETH)
    print(f"Listening for ERSPAN packets on {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start a TCP health listener for the decap script (default 9001)
    try:
        from health_endpoint import start_tcp_listener, start_http_status
    except Exception:
        from .health_endpoint import start_tcp_listener, start_http_status

    hp = int(os.environ.get('HEALTH_PORT', '9001'))
    ht = os.environ.get('HEALTH_TYPE', 'tcp')
    if ht.lower() == 'http':
        start_http_status(hp, path=os.environ.get('HEALTH_PATH', '/status'), name='decap-script')
    else:
        start_tcp_listener(hp, name='decap-script')

    main()
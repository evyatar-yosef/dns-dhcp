from random import randint
import random
from time import sleep
import time
from scapy.layers import dhcp
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff, sendp
from scapy.all import get_if_hwaddr
from scapy.all import conf

from scapy.all import *
import time

ip_address ="196.0.0.12" 
server_id = "196.0.0.11"
mac_address = get_if_hwaddr(conf.iface)

def handle_dhcp(pkt):
    global ip_address, server_id
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2: # DHCP Offer
        ip_address = pkt[BOOTP].yiaddr
        server_id = pkt[DHCP].options[2][1]
        request = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
            IP(src=ip_address, dst="255.255.255.255") / \
            UDP(sport=68, dport=67) / \
            BOOTP(op=1, chaddr=mac_address) / \
            DHCP(options=[("message-type", "request"),
                           ("server_id", server_id),
                           ("requested_addr", ip_address),
                           "end"])
        
        # Send DHCP Request
        sendp(request,iface=conf.iface)

        # Sniff DHCP ACK with a filter applied
        sniffed_pkt = sniff(filter="udp and (port 67 or 68)", timeout=3) 
       # and (src host " + server_id + " and dst host " + mac_address + ")", timeout=3)

        # Call handle_dhcp(pkt) function explicitly if a DHCP ACK message is sniffed
        if sniffed_pkt and DHCP in sniffed_pkt[0] and sniffed_pkt[0][DHCP].options[0][1] == 5:
            handle_dhcp(sniffed_pkt[0])
        print(sniffed_pkt.__len__) 
        # Print DHCP ACK options
        print("DHCP ACK received:")
        print(f"  IP address: {sniffed_pkt[0][BOOTP].yiaddr}")
        print(f"  Subnet mask: {sniffed_pkt[0][DHCP].options[1][1]}")
        print(f"  Default gateway: {sniffed_pkt[0][DHCP].options[3][1]}")
        print(f"  DNS server: {sniffed_pkt[0][DHCP].options[5][1]}")

# def handle_dhcp_ack(sniffed_pkt):
    
#     print("DHCP ACK received:")
#     print(f"  IP address: {sniffed_pkt[0][BOOTP].yiaddr}")
#     print(f"  Subnet mask: {sniffed_pkt[0][DHCP].options[1][1]}")
#     print(f"  Default gateway: {sniffed_pkt[0][DHCP].options[3][1]}")
#     print(f"  DNS server: {sniffed_pkt[0][DHCP].options[5][1]}")  
    
def send_request():
    global ip_address, server_id
    discover = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(op=1, chaddr=mac_address) / \
                    DHCP(options=[("message-type", "discover"), 
                                   ("broadcast_flag", ""), 
                                   ("requested_addr", "0.0.0.0"), # Set the requested IP address to 0.0.0.0
                                   "end"])
    sendp(discover, iface=conf.iface)
    sniffed_pkt = sniff(filter="udp and (port 67 or 68)", timeout=4)
    if sniffed_pkt:          
           handle_dhcp(sniffed_pkt[0])
def DHCP():
    send_request()  

def main():
    global ip_address, server_id
    user_input = input("Enter 1 to start sending DHCP discovery messages, or 0 to stop: ")
    while user_input == "1":
        send_request()       
        user_input = input("Enter 0 to stop sending DHCP discovery messages, or 1 to continue: ")
        if user_input == "0":
            break

if __name__ == "__main__":
    main()

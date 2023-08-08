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
from scapy.layers.dns import DNS, DNSQR, DNSRR


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
        # Print DHCP ACK options
        print("DHCP ACK received:")
        print(f"  IP address: {sniffed_pkt[0][BOOTP].yiaddr}")
        print(f"  Subnet mask: {sniffed_pkt[0][DHCP].options[1][1]}")
        print(f"  Default gateway: {sniffed_pkt[0][DHCP].options[3][1]}")
        print(f"  DNS server: {sniffed_pkt[0][DHCP].options[5][1]}")
        return sniffed_pkt[0][BOOTP].yiaddr
        

    
def dhco_request():
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
  

def DNS_PKT(client_ip):
    dns_server_ip = "5.29.14.36"
    # Get the domain name from the user
    domain_name = input("Enter a domain name: ").encode()
    # Create the DNS query packet
    dns_query = DNSQR(qname=domain_name)
    dns_pkt = Ether() / IP(dst=dns_server_ip) / UDP(sport=9999, dport=53) / DNS(rd=1, qd=dns_query)

   
    # Send the DNS query packet and sniff for the response
    sendp(dns_pkt, iface=conf.iface)
    response = sniff(filter="udp and port 9999", timeout=5)

    # Check if the domain name is in the DNS response
    if response and response[0].haslayer(DNSRR):
        ip_address = response[0][DNSRR].rdata

                
        print(f"The IP address of {domain_name.decode('utf-8')} is {ip_address}")
    else:
        print(f"The IP address of {domain_name.decode('utf-8')} is not here")
   

def main():
    global ip_address, server_id
    user_input = input("Enter 1 to start sending DHCP discovery messages, 2 to ask for domain, or 0 to stop: ")
    while user_input == "1":
        ip_address= dhco_request()       
        user_input = input("press 1 to send dns request or 0 to leave ")
        if user_input == "0":
            break        
        DNS_PKT(ip_address)
        user_input = input("press 1 for send a dhcp request or 0 to leave ")
        if user_input == "0":
            break       
    user_input = input("press 2 to send dns request or 0 to leave ")
    while user_input == "2":
        DNS_PKT(ip_address)

        
if __name__ == "__main__":
    main()

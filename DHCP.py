from telnetlib import IP
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
import random
import time

# Define subnet and IP pool range
subnet = '192.168.0.'
ip_pool = [subnet + str(i) for i in range(100, 201)]
local_ip = '1.1.1.1'

# Keep track of assigned IP addresses
leases = {}

# Assign an IP address to a client based on its MAC address
assigned_ips = set()

def assign_ip(mac_address):
    global ip_pool
    if mac_address in leases:
        return leases[mac_address]
    elif ip_pool:
        # Choose a random IP address from the available pool
        ip_address = random.choice(ip_pool)
        while ip_address in assigned_ips:  # Check if IP address is already assigned
            ip_address = random.choice(ip_pool)
        assigned_ips.add(ip_address)  # Add new IP address to set of assigned IPs
        print(f"Assigned IP address {ip_address} to {mac_address}")

        leases[mac_address] = ip_address
        return ip_address
    else:
        return None
    
# Packet processing function
def handle_dhcp(pkt):
    global ip_pool, leases, ip_address

    
    # If DHCP Discover message is received
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:        
        # Get the MAC address of the client
        mac_address = pkt[Ether].src        
        # Assign an IP address to the client
        ip_address = assign_ip(mac_address)        
        # If an IP address is available for assignment
        if ip_address:            
            # Record the lease in the leases dictionary
            leases[mac_address] = ip_address
            
            
            # Create a DHCP Offer packet to send to the client
            offer = Ether(src=get_if_hwaddr(conf.iface), dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src=local_ip, dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=ip_address, siaddr=local_ip, chaddr=mac_address) / \
                    DHCP(options=[("message-type", "offer"),
                                   ("subnet_mask", "255.255.255.0"),
                                   ("router", "196.0.0.10"),
                                   ("name_server", "196.0.0.11"),
                                   ("lease_time", 3600), "end"])
            
            # Send the DHCP Offer packet to the client
            time.sleep(1)
            sendp(offer, iface=conf.iface)  
            sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp)
              
                       
    # If DHCP Request message is received
    elif DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        
        # Get the MAC address and IP address requested by the client
        mac_address = pkt[Ether].src
        
        # ip_address = pkt[BOOTP].yiaddr
        # print(pkt[BOOTP].yiaddr)
        # Print a message to indicate the request
        print(f"Request for IP address {ip_address} from {mac_address}")
        
        # If the requested IP address is already assigned to another MAC address
        if 1>0:
        # mac_address in leases and leases[mac_address] != ip_address:
            
            # Create a DHCP NACK packet to send to the client
            ack = Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src) / \
                   IP(src=local_ip, dst="255.255.255.255") / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=ip_address, siaddr=pkt[BOOTP].siaddr, chaddr=mac_address) / \
                   DHCP(options=[("message-type", "offer"),
                                   ("subnet_mask", "255.255.255.0"),
                                   ("router", "196.0.0.10"),
                                   ("name_server", "196.0.0.11"),
                                   ("lease_time", 3600), "end"])
            
            time.sleep(1)
            print(local_ip,ip_address, pkt[BOOTP].siaddr,mac_address)

            # Send the DHCP NACK packet to the client
            sendp(ack, iface=conf.iface)
            # print(local_ip,ip_address, pkt[BOOTP].siaddr,mac_address)
            # Print a message to indicate the IP address is already assigned to another MAC address
            print(f"IP address {ip_address} already assigned to another MAC address")



# Start the DHCP server
def main():
    print("Starting DHCP server...")
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp)

if __name__ == '__main__':
    main()
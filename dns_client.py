from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Define the DNS server IP address
dns_server_ip = "5.29.14.36"

# Define the domain name to query
domain_name = b"google.com"

# Create the DNS query packet
dns_query = DNSQR(qname=domain_name)

dns_pkt = Ether() / IP(dst=dns_server_ip) / UDP(sport = 9999,dport=53) / DNS(rd=1, qd=dns_query)

# Define the function to handle incoming DNS responses
def handle_dns_response(pkt):
    print("tre")
    if pkt.haslayer(DNSRR) and pkt[DNS].id == dns_pkt[DNS].id:
        ip_address = pkt[DNSRR].rdata
        print(f"The IP address of {domain_name.decode('utf-8')} is {ip_address}")

# Send the DNS query packet and sniff for the response
sendp(dns_pkt,iface=conf.iface)
sniff(filter= "udp and port 9999" ,prn=handle_dns_response, timeout=5)

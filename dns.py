from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Define the mapping between domain names and IP addresses
dns_records = {
    b"example.com": "192.168.1.100",
    b"google.com": "8.8.8.8",
    b"facebook.com": "31.13.76.102"
}

def dns_server():
    while True:
        pkt = sniff(filter="udp port 53", count=1)[0]
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            # DNS query
            dns_req = pkt.getlayer(DNSQR).qname
            dns_query = dns_req.decode('utf-8').rstrip('.')
            dns_qtype = pkt.getlayer(DNSQR).qtype
            dns_qclass = pkt.getlayer(DNSQR).qclass

            try:
                if dns_query.encode() in dns_records:
                    # Create the DNS response
                    dns_resp = Ether(dst ="ff:ff:ff:ff", src=pkt[Ether].dst) / \
                               IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                               UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                               DNS(id=pkt[DNS].id, qr=1, rd=1, qd=dns_req, \
                               an=DNSRR(rrname=dns_req, rdata=dns_records[dns_query.encode()]))

                    # Send the DNS response back to the client
                    sendp(dns_resp)
                    print(f"DNS response sent: {dns_query} -> {dns_records[dns_query.encode()]}")

                else:
                    # Create a DNS response with an empty answer 
                    dns_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                               UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                               DNS(id=pkt[DNS].id, qr=1, qd=dns_req, an=DNSRR(rrname=dns_req, rdata="0.0.0.0"))

                    # Send the DNS response back to the client
                    print(f"No record found for {dns_query}, sending empty response")   
                    sendp(dns_resp)

            except KeyError:
                ip_address = "0.0.0.0" 

if __name__ == '__main__':
    # Start sniffing for incoming DNS requests
    print("DNS server started...")
    dns_server()

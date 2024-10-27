from scapy.all import *

# ANSI escape codes for colors and formatting
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

def packet_callback(packet):
    # Check if the packet has a DNS layer
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        # Extract source and destination IPs
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Extract source and destination ports
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

        # Determine packet type (Request or Response)
        packet_type = "DNS Request" if dns_layer.qr == 0 else "DNS Response"

        # Print the colored and bold header for packet type
        print(f"\n{BOLD}{BLUE}[+] {packet_type} Captured:{RESET}")

        # Print basic IP and port information with color
        print(f"{YELLOW}    Source IP: {GREEN}{src_ip}{RESET} -> {YELLOW}Destination IP: {GREEN}{dst_ip}{RESET}")
        print(f"{YELLOW}    Source Port: {GREEN}{src_port}{RESET} -> {YELLOW}Destination Port: {GREEN}{dst_port}{RESET}")

        # If it's a DNS request
        if dns_layer.qr == 0:
            query_name = packet[DNSQR].qname.decode('utf-8')
            query_type = packet[DNSQR].qtype
            print(f"{YELLOW}    DNS Request: {BLUE}{query_name}{RESET}")
            print(f"{YELLOW}    Query Type: {GREEN}{dns_query_type(query_type)}{RESET}")

        # If it's a DNS response
        elif dns_layer.qr == 1:
            response_name = packet[DNSRR].rrname.decode('utf-8')
            response_data = packet[DNSRR].rdata
            ttl = packet[DNSRR].ttl
            print(f"{YELLOW}    DNS Response for: {BLUE}{response_name}{RESET}")
            print(f"{YELLOW}    Resolved IP: {GREEN}{response_data}{RESET}")
            print(f"{YELLOW}    TTL: {GREEN}{ttl} seconds{RESET}")

def dns_query_type(query_type):
    # Map DNS query types to human-readable format
    query_types = {
        1: "A (IPv4 address)",
        28: "AAAA (IPv6 address)",
        15: "MX (Mail Exchange)",
        16: "TXT (Text Record)",
        6: "SOA (Start of Authority)"
    }
    return query_types.get(query_type, "Other")

# Start sniffing the network and apply the packet_callback function on each packet
print(f"{BOLD}{GREEN}Sniffing for DNS packets...{RESET}")
sniff(filter="udp port 53", prn=packet_callback, store=0)

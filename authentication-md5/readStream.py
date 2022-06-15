from scapy.all import *
from scapy.layers.inet import UDP
from scapy.layers.rtp import *
# len <= 390 and len >= 370 and
capture = sniff(filter="len >= 370 && src host 192.168.1.3 && dst host 192.168.1.108 && tcp dst port 554",
                iface=conf.iface, count=30)
capture.summary()
wrpcap("GfG.pcap", capture)

# bind_layers(UDP, RTP, dport=5016)
# pkts = sniff(offline="GfG.pcap")  # , filter="src host 192.168.1.4 and dst host 192.168.1.108")
#
# for pkt in pkts:
#     pkt.show()
#     # if pkt["UDP"].dport == 5016:
#     #     pkt["UDP"].payload = RTP(pkt["Raw"].load)

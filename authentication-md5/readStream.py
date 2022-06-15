from threading import Thread
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.rtp import *


def handle_packet(pkt):
    # pkt.show()
    payload = pkt[TCP].payload
    # print('joe joe')
    print(payload)
    sys.exit()
    # if pkt.__contains__('rtsp://'):
    #     print(pkt)


def sniff_function():
    capture = sniff(filter="len >= 370 && src host 192.168.1.3 && dst host 192.168.1.108 && tcp dst port 554",
                    iface=conf.iface, prn=handle_packet)
    capture.summary()


thread = Thread(target=sniff_function)
thread.start()
thread.join()

print("joe joe")

# capture.summary()
# wrpcap("GfG.pcap", capture)

# bind_layers(UDP, RTP, dport=5016)
# pkts = sniff(offline="GfG.pcap")  # , filter="src host 192.168.1.4 and dst host 192.168.1.108")
#
# for pkt in pkts:
#     pkt.show()
#     # if pkt["UDP"].dport == 5016:
#     #     pkt["UDP"].payload = RTP(pkt["Raw"].load)

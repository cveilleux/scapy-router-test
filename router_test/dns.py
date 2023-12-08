from scapy.layers.dns import DNS, DNSQR
import random

from scapy.layers.inet import UDP


def build_dns_request(qname):
    xid = random.randint(0, 65535)
    udp = UDP(dport=53) / DNS(id=xid, rd=1, qd=DNSQR(qname=qname))
    return xid, udp


def get_first_dns_record_data(packet):
    if packet and packet.haslayer(DNS) and packet[DNS].ancount:
        for x in range(packet[DNS].ancount):
            return packet[DNS].an[x].rdata

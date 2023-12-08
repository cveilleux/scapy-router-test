import random
import time

from scapy.data import MTU
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from threading import Thread

from scapy.sendrecv import sendp, sniff, AsyncSniffer
from scapy.supersocket import L3RawSocket

from router_test import logger


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class TcpSession:
    CONNECT_SUCCESS = 0
    CONNECT_TIMEOUT = 1
    CONNECT_RESET = 2

    def __init__(self, ifname, src_mac, src_ip, router_mac, target_ip, target_port):
        self.seq = 0
        self.ack = 0
        self.eth = Ether(src=src_mac, dst=router_mac)
        self.ip = IP(src=src_ip, dst=target_ip)
        self.sport = random.randint(13000, 13999)
        self.dport = target_port
        self.connected = False
        self._ackThread = None
        self._timeout = 3

        self.ifname = ifname

        self.packets = []

    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[TCP].payload)
        ack = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        self.sendp(ack)

    def _ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = self.srp1(fin_ack, lfilter=lambda p: p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].ack == self.seq + 1 and p[TCP].flags & ACK == ACK)
        self.seq += 1

        if not ack:
            logger.debug("_ack_rclose: no response received. Connection not cleanly closed.")

    def _sniff(self):
        s = L3RawSocket(iface=self.ifname)
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and (p.haslayer(Raw) or p.haslayer(HTTP)) \
                    and p[TCP].dport == self.sport:
                self._ack(p)
                logger.debug("packet ack'd and kept")
                self.packets.append(p)

            if p.haslayer(TCP) and p[TCP].dport == self.sport \
                    and p[TCP].flags & FIN == FIN:  # FIN
                self._ack_rclose()
                logger.debug("packet ack_rclose'd and kept")
                self.packets.append(p)

        s.close()
        self._ackThread = None
        logger.debug('Acknowledgment thread stopped')

    def _start_ackThread(self):
        self._ackThread = Thread(name='AckThread', target=self._sniff, daemon=True)
        self._ackThread.start()

    def connect(self):
        self.seq = random.randrange(0, (2 ** 32) - 1)

        def check_packet(p):
            return p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].ack == self.seq + 1

        syn = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        syn_ack = self.srp1(syn, lfilter=check_packet)
        self.seq += 1

        if not syn_ack:
            return TcpSession.CONNECT_TIMEOUT

        elif syn_ack[TCP].flags & RST == RST:
            return TcpSession.CONNECT_RESET

        self.ack = syn_ack[TCP].seq + 1
        ack = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        self.sendp(ack)

        self.connected = True
        self._start_ackThread()
        return TcpSession.CONNECT_SUCCESS

    def close(self):
        self.connected = False

        # fin = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        # fin_ack = self.srp1(fin, lfilter=lambda p: p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].ack == self.seq + 1 and p[TCP].flags & 0x11 == 0x11)
        # self.seq += 1
        #
        # if not fin_ack:
        #     logger.warning("tcp: timed-out waiting for fin_ack when closing connection")
        #
        # else:
        #     self.ack = fin_ack[TCP].seq + 1
        #     ack = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        #     self.sendp(ack)

        packets = self.packets
        self.packets = []
        return packets

    def build(self, payload):
        psh = self.eth / self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload
        self.seq += len(psh[Raw])
        return psh

    def send(self, payload):
        psh = self.build(payload)

        def check_packet(p):
            return p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].ack == self.seq and p[TCP].flags & ACK == ACK

        ack = self.srp1(psh, lfilter=check_packet)

        if not ack:
            logger.warning("tcp: send payload: No ack received, send failed...")
            return

    def sendp(self, packet):
        sendp(packet, iface=self.ifname, verbose=0)

    def srp1(self, packet, lfilter=None):
        def started_cb():
            self.sendp(packet)

        sniffer = AsyncSniffer(iface=self.ifname, count=1, timeout=self._timeout, started_callback=started_cb, lfilter=lfilter)
        sniffer.start()
        sniffer.join()
        if sniffer.results:
            return sniffer.results[0]
        else:
            logger.debug("Timed out waiting for reply to")
            logger.debug(packet)

"""
scapy based dhcp client.
"""
import binascii
import ipaddress
from typing import Dict, List

import platform
from threading import Thread, Event
import time

from ipaddress import IPv4Network

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.packet import Packet

# conf.use_pcap = True
# import scapy.arch.pcapdnet

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP, DHCPTypes
from scapy.sendrecv import AsyncSniffer, sendp
from scapy.volatile import RandInt

from . import get_logger


DISCOVER_TIMEOUT = 30
ACK_TIMEOUT = 30

DEFAULT_LEASE_TIME = 86400


def mac_str_to_binary(mac_str):
    return binascii.unhexlify(mac_str.replace(":", ""))


def normalize_name_servers(name_servers):
    if not name_servers:
        return None

    if type(name_servers) not in (list, tuple):
        raise ValueError(f"Invalid name servers: {name_servers}")

    normalized = []
    for ns in name_servers:
        if type(ns) != str:
            raise ValueError(f"Invalid name server: {ns}")

        normalized.append(str(ipaddress.ip_address(ns)))

    return normalized


class DHCPPacket:

    packet: Packet
    received_time: float
    dst_mac: str
    src_mac: str
    src_ip: str
    message_type: str
    dhcp_options: Dict
    xid: int
    yiaddr: str

    def __init__(self, packet: Packet, client: "DHCPClient"):
        self.client = client
        self.received_time = int(time.time())

        if not packet.haslayer(DHCP):
            raise ValueError("Not a DHCP packet.")

        self.packet = packet

        if packet.haslayer(Ether):
            self.dst_mac = packet.getlayer(Ether).dst
            self.src_mac = packet.getlayer(Ether).src

        if packet.haslayer(IP):
            self.src_ip = packet.getlayer(IP).src

        self.dhcp_options = self._parse_dhcp_options(packet[DHCP].options)

        self.message_type = None
        message_type_int = self.dhcp_options.get("message-type")
        if message_type_int:
            self.message_type = DHCPTypes.get(message_type_int)

        self.xid = self.packet.getlayer(BOOTP).xid
        self.yiaddr = self.packet.getlayer(BOOTP).yiaddr

    def _parse_dhcp_options(self, options_list):
        """
        dhcp options are returned by scapy as a list of tuples.
        the first item of each tuple is the key, and the remaining items are the values.
        """
        dhcp_options = dict()
        for opt_tuple in options_list:
            if type(opt_tuple) != tuple:
                continue

            if len(opt_tuple) < 2:
                continue

            if len(opt_tuple) == 2:
                dhcp_options[opt_tuple[0]] = opt_tuple[1]

            else:
                dhcp_options[opt_tuple[0]] = opt_tuple[:1]

        return dhcp_options

    @property
    def router(self):
        return self.dhcp_options.get("router")

    @property
    def server_id(self):
        return self.dhcp_options.get("server_id")

    @property
    def subnet_mask(self):
        return self.dhcp_options.get("subnet_mask")

    @property
    def lease_time(self):
        return self.dhcp_options.get("lease_time", DEFAULT_LEASE_TIME)

    @property
    def renewal_time(self):
        return self.dhcp_options.get("renewal_time", self.lease_time / 2)

    @property
    def rebinding_time(self):
        return self.dhcp_options.get("rebinding_time", self.lease_time / 2)

    @property
    def name_server(self):
        dns = self.dhcp_options.get("name_server")
        if type(dns) == str:
            dns = [
                dns,
            ]

        try:
            return normalize_name_servers(dns)
        except Exception as e:
            self.client.logger.warning(f"Invalid name servers ({dns}) received in DHCP offer: {e}")

    @property
    def ip_addr_cidr(self):
        prefixlen = IPv4Network("0.0.0.0/{0}".format(self.subnet_mask)).prefixlen
        return "{0}/{1}".format(self.yiaddr, prefixlen)

    def is_valid_offer(self, xid: int):
        if not self.server_id:
            self.client.logger.warning("Missing server_id option in offer.")
            return False

        if not self.subnet_mask:
            self.client.logger.warning("Missing subnet_mask in offer.")
            return False

        if not self.yiaddr:
            self.client.logger.warning("Missing yiaddr in offer.")
            return False

        if not self.lease_time:
            self.client.logger.warning(f"Missing lease_time. Default of {DEFAULT_LEASE_TIME} will be used.")

        if self.xid != xid:
            self.client.logger.warning("xid mismatch in offer: {0}, expected {1}".format(self.xid, xid))
            return False

        return True

    def is_valid_nak(self, xid: int):
        if self.xid != xid:
            self.client.logger.warning("xid mismatch in nak: {0}, expected {1}".format(self.xid, xid))
            return False

        return True


class Lease:
    STATUS_EMPTY = "EMPTY"
    STATUS_OFFERED = "OFFERED"
    STATUS_VALID = "VALID"
    STATUS_RENEWABLE = "RENEWABLE"
    STATUS_REBINDABLE = "REBINDABLE"
    STATUS_EXPIRED = "EXPIRED"

    offer: DHCPPacket
    ack: DHCPPacket

    request_attempts: int
    force_renew: bool

    def __init__(self, renew_from: "Lease" = None):
        if renew_from:
            self.xid = renew_from.xid
            self.offer = renew_from.offer

        else:
            self.xid = int(RandInt())
            self.offer = None

        self.request_attempts = 0
        self.ack = None
        self.force_renew = False

    @property
    def status(self):
        if self.ack:
            if self.ack.received_time + self.ack.lease_time < time.time():
                return Lease.STATUS_EXPIRED

            if self.ack.received_time + self.ack.rebinding_time < time.time():
                return Lease.STATUS_REBINDABLE

            if self.force_renew or self.ack.received_time + self.ack.renewal_time < time.time():
                return Lease.STATUS_RENEWABLE

            return Lease.STATUS_VALID

        elif self.offer:
            return Lease.STATUS_OFFERED

        return Lease.STATUS_EMPTY


class DHCPClient:
    STATUS_STOPPED = "STOPPED"
    STATUS_DISCOVERING = "DISCOVERING"
    STATUS_REQUESTING = "REQUESTING"
    STATUS_RENEWING = "RENEWING"
    STATUS_BOUND = "BOUND"

    interface: str
    hostname: str
    request_nameservers: bool
    request_gateway: bool
    set_default_gateway: bool

    mac_str: str
    mac_bin: bytes
    lease_acquired_listeners: List[callable]

    status: str

    acquired_lease: Lease
    next_lease: Lease

    def __init__(
        self,
        interface: str,
        hostname: str = None,
        request_nameservers: bool = False,
        request_gateway: bool = True,
    ):
        """
        :param interface: The interface name on which to operate.
        :param hostname: Our hostname to present to the dhcp server.
        :param request_nameservers: Request and set nameservers.
        :param request_gateway: Request a router and set it as the default gateway if provided.
        """
        conf.checkIPaddr = False

        self.interface = interface
        self.hostname = hostname or platform.node()
        self.request_nameservers = request_nameservers
        self.request_gateway = request_gateway

        # list of callables to notify when a new lease is acquired
        self.lease_acquired_listeners = []

        self.mac_str = get_if_hwaddr(self.interface)
        self.mac_bin = mac_str_to_binary(self.mac_str)

        self.status = DHCPClient.STATUS_STOPPED
        self.sleep_for = 60

        self.acquired_lease = None
        self.next_lease = None

        self.sniffer = AsyncSniffer(
            store=False,
            count=0,
            filter="udp and dst port 68",
            iface=self.interface,
            prn=self._lease_thread_recv,
        )

        self._stop_event = None
        self._lease_thread = None

        self.logger = get_logger(f"dhcp-{self.interface}")

    def on_lease_acquired(self, listener: callable):
        """
        Register a callable function to notify when a new lease is acquired.
        The callback function will receive 2 args: dhcpclient, lease
        """
        self.lease_acquired_listeners.append(listener)

    def start(self):
        if self.status != DHCPClient.STATUS_STOPPED:
            raise ValueError("Already started.")

        if self._stop_event and self._stop_event.is_set():
            raise ValueError("Restarting a used dhcp client is not supported. Create a new one.")

        self.logger.info(f"Starting on {self.interface} with mac addr {self.mac_str}")

        self._lease_thread = Thread(target=self._lease_thread_run, daemon=True)
        self._stop_event = Event()
        self.status = DHCPClient.STATUS_DISCOVERING
        self.sleep_for = 5
        self.next_lease = Lease()
        self._lease_thread.start()

    def is_stopped(self):
        return self._stop_event and self._stop_event.is_set()

    def stop(self):
        if self._stop_event:
            self._stop_event.set()

    def force_renew(self):
        if (
            self.status == DHCPClient.STATUS_STOPPED
            or not self._stop_event
            or self._stop_event.is_set()
        ):
            self.logger.warning("DHCP renewal requested but client is stopped. Ignoring.")
            return

        if not self.acquired_lease or self.acquired_lease.status != Lease.STATUS_VALID:
            self.logger.warning("DHCP renewal requested but no valid lease to renew. Ignoring.")
            return

        self.acquired_lease.force_renew = True

    def _start_sniffer(self):
        if self.sniffer.running:
            return
        self.sniffer.start()
        time.sleep(1)

    def _stop_sniffer(self):
        if self.sniffer.running:
            self.sniffer.stop()

    def _lease_thread_run(self):
        while True:
            if self._stop_event.is_set():
                self.logger.info("Stopping dhcp client on interface {0}".format(self.interface))
                self._stop_sniffer()
                self.status = DHCPClient.STATUS_STOPPED
                self.next_lease = None
                return

            if self.acquired_lease:
                # See if it is time to renew
                acquired_lease_status = self.acquired_lease.status
                if acquired_lease_status == Lease.STATUS_RENEWABLE:
                    if self.status != DHCPClient.STATUS_RENEWING:
                        self.logger.info("Bound lease is renewable. Starting renew process.")
                        self.status = DHCPClient.STATUS_RENEWING
                        self.next_lease = Lease(renew_from=self.acquired_lease)
                        self._start_sniffer()

                elif acquired_lease_status in (
                    Lease.STATUS_EXPIRED,
                    Lease.STATUS_REBINDABLE,
                ):
                    if self.status not in (
                        DHCPClient.STATUS_REQUESTING,
                        DHCPClient.STATUS_DISCOVERING,
                    ):
                        self.logger.info(
                            "Bound lease is expired or rebindable. Starting discover process."
                        )
                        self.status = DHCPClient.STATUS_DISCOVERING
                        self.sleep_for = 5
                        self.next_lease = Lease(renew_from=self.acquired_lease)
                        self._start_sniffer()

                else:
                    self.status = DHCPClient.STATUS_BOUND
                    self._stop_sniffer()
                    self.sleep_for = 10

            if self.status == DHCPClient.STATUS_DISCOVERING:
                if self.next_lease is None:
                    self.next_lease = Lease()

                self._start_sniffer()
                self.logger.info("Sending DISCOVER packet.")
                self._sendp(self._build_dhcp_discover(self.next_lease))
                self.sleep_for = min(self.sleep_for + 5, 30)

            elif self.status == DHCPClient.STATUS_RENEWING:
                self.next_lease = Lease(self.acquired_lease)
                self._start_sniffer()
                self.status = DHCPClient.STATUS_REQUESTING
                self.logger.info("Starting renewal. Sending REQUEST packet.")
                self._sendp(self._build_dhcp_request(self.next_lease))
                self.sleep_for = 10

            elif self.status == DHCPClient.STATUS_REQUESTING:
                if self.next_lease.request_attempts > 5:
                    self.logger.warning(
                        "Failed to acquire lease after 5 request attempts. Going back to DISCOVER mode."
                    )
                    self.status = DHCPClient.STATUS_DISCOVERING
                    self.next_lease = None
                    self.sleep_for = 10
                else:
                    self.next_lease.request_attempts += 1
                    self.logger.info(
                        "Sending REQUEST packet (retry number {0}).".format(
                            self.next_lease.request_attempts
                        )
                    )
                    self._sendp(self._build_dhcp_request(self.next_lease))
                    self.sleep_for = 10

            self._stop_event.wait(self.sleep_for)

    def _sendp(self, packet):
        try:
            sendp(
                packet,
                iface=self.interface,
                verbose=False,
            )
        except OSError as e:
            self.logger.error(f"Failed to send packet: {e}")

    def _lease_thread_recv(self, packet):
        try:
            dhcp_packet = DHCPPacket(packet, self)
        except ValueError:
            self.logger.warning("Not a DHCP packet. Ignoring.")
            return

        if dhcp_packet.message_type == "offer":
            if dhcp_packet.dst_mac not in (self.mac_str, "ff:ff:ff:ff:ff:ff"):
                self.logger.warning(
                    f"Received offer is not for us: {dhcp_packet.dst_mac}, expected {self.mac_str}. Ignoring."
                )
                return

            if self.status != DHCPClient.STATUS_DISCOVERING:
                self.logger.warning(
                    "Received a DHCP offer but we are not in discovery status. Ignoring."
                )
                return

            if not self.next_lease:
                self.logger.warning(
                    "Received a DHCP offer but we have not sent a DISCOVER yet. Ignoring."
                )
                return

            if not dhcp_packet.is_valid_offer(self.next_lease.xid):
                self.logger.warning("Received an invalid DHCP offer. Ignoring.")
                return

            self.logger.info("Sending initial REQUEST packet.")
            self.status = DHCPClient.STATUS_REQUESTING
            self.next_lease.offer = dhcp_packet

            self._sendp(self._build_dhcp_request(self.next_lease))

        elif dhcp_packet.message_type == "nak":
            if self.status != DHCPClient.STATUS_REQUESTING:
                self.logger.warning(
                    "Received a DHCP nak but we are not in requesting status. Ignoring."
                )
                return

            if not dhcp_packet.is_valid_nak(self.next_lease.xid):
                self.logger.warning("Received an invalid DHCP nak (xid mismatch). Ignoring.")
                return

            self.logger.info(
                "DHCP server rejected our request (NAK). Going back into DISCOVERING state."
            )
            self.status = DHCPClient.STATUS_DISCOVERING
            self.acquired_lease = None
            self.next_lease = None

        elif dhcp_packet.message_type == "ack":
            if self.status != DHCPClient.STATUS_REQUESTING:
                self.logger.warning(
                    "Received a DHCP ack but we are not in requesting status. Ignoring."
                )
                return

            self.next_lease.ack = dhcp_packet
            self._lease_acquired(self.next_lease)

    def _lease_acquired(self, lease):
        self.status = DHCPClient.STATUS_BOUND
        self.next_lease = None
        self.acquired_lease = lease

        acquired_ip_addr = self.acquired_lease.offer.ip_addr_cidr

        expiring_in = self.acquired_lease.ack.lease_time - (
            int(time.time()) - self.acquired_lease.ack.received_time
        )
        if expiring_in < 0:
            self.logger.error(
                "Cannot set IP address of acquired lease: The lease is already expired."
            )
            return

        # Add or replace the new ip addr and set valid time
        self.logger.info(f"Received DHCP lease: {acquired_ip_addr} on interface {self.interface} for {expiring_in} seconds")

        # Add or update default gateway
        if self.request_gateway:
            new_gateway = self.acquired_lease.offer.router
            if new_gateway:
                self.logger.info(f"Default gateway should be set to: {new_gateway}")

            else:
                self.logger.warning(
                    "A default gateway (router) was requested, but DHCP lease did not provide any. "
                    "No route will be added."
                )

        if self.request_nameservers:
            name_servers = self.acquired_lease.offer.name_server
            if not name_servers:
                self.logger.warning(f"DHCP offer did not contain name servers even though we asked for it.")
            self.logger.info(f"Name servers received: {name_servers}")

        for listener in self.lease_acquired_listeners:
            listener(self, lease)

    def _build_dhcp_discover(self, lease):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_str)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(xid=lease.xid, op=1, chaddr=self.mac_bin)
        param_req_list = (1,)  # subnet
        if self.request_gateway:
            param_req_list = *param_req_list, 3  # router
        if self.request_nameservers:
            param_req_list = *param_req_list, 6  # DNS
        dhcp = DHCP(
            options=[
                ("message-type", "discover"),
                ("hostname", self.hostname),
                # ("client_id", self.hwaddr),
                # ("vendor_class_id", "chinookd"),
                ("param_req_list", *param_req_list),
                "end",
            ]
        )

        return ether / ip / udp / bootp / dhcp

    def _build_dhcp_request(self, lease: Lease):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_str)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(xid=lease.xid, op=1, chaddr=self.mac_bin)
        dhcp = DHCP(
            options=[
                ("message-type", "request"),
                ("hostname", self.hostname),
                ("requested_addr", lease.offer.yiaddr),
                ("server_id", lease.offer.server_id),
                ("end"),
            ]
        )

        return ether / ip / udp / bootp / dhcp

import dataclasses
import random
import sys
import time
from ipaddress import ip_network
import socket

from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sendp, AsyncSniffer

from router_test import logger, random_string
from router_test.dhcp import DHCPClient
from router_test.dns import get_first_dns_record_data, build_dns_request
from router_test.ethtool import get_ethtool_info
from router_test.tcp import TcpSession

BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

DHCP_TIMEOUT = 15

DNS_TESTS = ["example.org"]

GOOGLE_IP = "8.8.8.8"
OPENDNS_IP = "208.67.222.222"
CLOUDFLARE_IP = "1.1.1.1"
PING_INTERNET_IPS = [GOOGLE_IP, OPENDNS_IP, CLOUDFLARE_IP]


@dataclasses.dataclass
class TargetHost:
    name: str
    ip: str
    open_ports: tuple[int]


# Attempt to arp/ping aross vlans. There is no way to discover these targets to they need to be configured per your
# setup.
# TODO: Load from config file / options
CROSS_VLAN_TARGETS = [
    TargetHost(name="example1", ip="192.168.230.209", open_ports=(22,)),
    TargetHost(name="example1", ip="192.168.236.105", open_ports=None),
]


@dataclasses.dataclass
class ConnectCheck:
    name: str
    domain: str
    path: str
    expected_status: int


CONNECT_CHECKS = [
    ConnectCheck(name="ubuntu", domain="connectivity-check.ubuntu.com", path="/", expected_status=204),
    ConnectCheck(name="microsoft", domain="www.msftconnecttest.com", path="/connecttest.txt", expected_status=200),
    ConnectCheck(name="google", domain="connectivitycheck.gstatic.com", path="/generate_204", expected_status=204),
    ConnectCheck(name="apple", domain="www.apple.com", path="/library/test/success.html", expected_status=200),
]


def fail(msg="unknown error"):
    logger.error(f"Test failed: {msg}")
    sys.exit(1)


def log_test(test, message, level=logger.info):
    level("{0:16} {1}".format(f"[{test}]", message))


def main():
    if len(sys.argv) != 2:
        print("usage: " + sys.argv[0] + " [ifname]", file=sys.stderr)
        sys.exit(1)
    ifname = sys.argv[1]

    hostname = "test-" + random_string(6)
    logger.info(f"Router test on interface {ifname} using hostname: {hostname}")

    link, eth_info, eth_mode = get_ethtool_info(ifname)
    carrier = "UP" if link.get_attr("IFLA_CARRIER") == 1 else "DOWN"
    logger.info(f"Carrier: {carrier}")
    if eth_mode:
        logger.info(f"Speed: {eth_mode.speed} ({eth_mode.duplex} duplex)")

    src_mac = link.get_attr("IFLA_ADDRESS")
    logger.info(f"Mac addr: {src_mac}")

    if carrier != "UP":
        logger.error("No ethernet carrier, nothing to test.")
        fail("No carrier")

    test = RouterTest(ifname, hostname, src_mac)
    test.start()


class RouterTest:

    def __init__(self, ifname, hostname, src_mac):
        self.ifname = ifname
        self.hostname = hostname
        self.dhcp_client = None
        self.dhcp_lease = None

        self.src_mac = src_mac
        self.src_ip = None
        self.router_ip = None
        self.router_mac = None

    def start(self):
        self.do_dhcp()

        self.start_arp_responder()
        self.send_gratuitous_arp()

        self.do_ping_router()

        self.do_test_dns()

        for dst in PING_INTERNET_IPS:
            self.do_ping_internet(dst)

        for check in CONNECT_CHECKS:
            self.do_connectivity_check(check)

        arp_clients = self.do_arp_scan_subnet()
        self.do_ping_clients(arp_clients)

        self.do_arping_cross_vlan()

        self.do_ping_cross_vlan()

        self.do_tcp_connect_cross_vlan()

        arp_hosts = self.do_arp_scan_common_networks()
        self.do_ping_clients(arp_hosts)

        for ip, mac in arp_hosts.items():
            self.do_open_admin_page(ip, mac)

    def do_dhcp(self):
        logger.info(f"Starting DHCP client on interface {self.ifname}")
        self.dhcp_client = DHCPClient(self.ifname, hostname=self.hostname, request_nameservers=True, request_gateway=True)
        self.dhcp_client.on_lease_acquired(self.on_lease_acquired)
        self.dhcp_client.start()

        dhcp_timeout = 0
        while self.dhcp_client.status != DHCPClient.STATUS_BOUND:
            logger.info(f"dhcp client is in state {self.dhcp_client.status}. Waiting...")
            dhcp_timeout += 1
            if dhcp_timeout == DHCP_TIMEOUT:
                fail(f"Timed out waiting for a DHCP lease after {DHCP_TIMEOUT} seconds.")
            time.sleep(1)

    def on_lease_acquired(self, client, lease):
        logger.info("DHCP lease acquired.")
        self.dhcp_lease = lease
        self.src_ip = lease.offer.yiaddr
        self.router_ip = lease.offer.router
        self.router_mac = lease.offer.src_mac

    def start_arp_responder(self):
        sniffer = AsyncSniffer(iface=self.ifname, filter="arp", lfilter=self.handle_arp)
        sniffer.start()

    def handle_arp(self, packet):
        if packet[ARP].op == 1:
            if packet.pdst == self.src_ip and packet.hwsrc != self.src_mac:
                log_test("arp_responder", f"Responding to arp from {packet.hwsrc} / {packet.psrc}")
                reply = self.eth_packet(packet.hwsrc) / ARP(op=2, hwsrc=self.src_mac, psrc=self.src_ip)
                self.sendp(reply)

    def send_gratuitous_arp(self):
        arp = ARP(psrc=self.src_ip,
                  hwsrc=self.src_mac,
                  pdst=self.src_ip)
        packet = self.eth_packet(dst=BCAST_MAC) / arp
        self.sendp(packet)

    def do_ping_router(self):
        ping_response, ping_delay = self.send_ping(self.router_mac, self.router_ip)
        if not ping_response:
            log_test("ping_router", f"Cannot ping router {self.router_ip} from dhcp assigned ip: {self.src_ip}", level=logger.warning)
        else:
            log_test("ping_router", f"Success: Got reply in {ping_delay} msecs.")

    def do_test_dns(self):
        for domain in DNS_TESTS:
            self.do_test_dns_single(domain)
        for check in CONNECT_CHECKS:
            self.do_test_dns_single(check.domain)

    def do_test_dns_single(self, domain):
        hostname, aliaslist, expected_ips = socket.gethostbyname_ex(domain)
        if not expected_ips:
            log_test("test_dns", f"Could not resolve {domain}. Make sure you have a working network connection other than the tested one.", level=logger.warning)

        name_servers = self.dhcp_lease.offer.name_server
        if name_servers != [self.router_ip]:
            fail("Expected dhcp assigned name servers to be router ip. Got: " + name_servers)
        dns_response = self.resolve_dns(domain)
        if not dns_response:
            fail(f"Got no DNS reply from {self.router_ip} when querying for {domain}.")
        if expected_ips and dns_response not in expected_ips:
            fail(f"Received {dns_response} DNS response for {domain}. Expected one of {expected_ips}.")
        log_test("test_dns", f"Success: {self.router_ip} responds to DNS for {domain} with valid IP ({dns_response}).")

    def resolve_dns(self, domain):
        xid, dns_req = self.dns_packet(self.router_mac, self.router_ip, qname=domain)
        dns_response, dns_delay = self.srp1_time(dns_req, lfilter=lambda p: p.haslayer(DNS) and p[DNS].id == xid and p[DNS].ancount)
        if not dns_response:
            return

        data = get_first_dns_record_data(dns_response)

        # cnames are returned as bytes
        if type(data) == bytes:
            return self.resolve_dns(data)

        return data

    def do_arping_cross_vlan(self):
        for target in CROSS_VLAN_TARGETS:
            answered = self.arping(target.ip)
            if answered:
                original_packet, answer = answered[0]
                log_test("arping_cross", f"{target.name} is reachable using arp ping to {target.ip}: Mac address discovered: {answer.src}", level=logger.warning)
                ping_response, ping_delay = self.send_ping(answer.src, target.ip)
                if not ping_response:
                    log_test("arping_cross", f"{target.ip} does NOT respond to ICMP pings.")
                else:
                    log_test("arping_cross", f"{target.ip} responds to ICMP pings in {ping_delay} msecs.", level=logger.warning)

            else:
                log_test("arping_cross",
                         f"{target.name} is NOT reachable using arp ping to {target.ip}: No answer received.")

    def arping(self, target_ip):
        return self.srp1(
            self.eth_packet(dst=BCAST_MAC) / ARP(hwsrc=self.src_mac, pdst=target_ip),
            filter="arp and arp[7] = 2",
            lfilter=lambda p: p[ARP].psrc == target_ip,
        )

    def do_ping_cross_vlan(self):
        for target in CROSS_VLAN_TARGETS:
            ping_response, ping_delay = self.send_ping(self.router_mac, target.ip)
            if not ping_response:
                log_test("ping_cross", f"{target.ip} does NOT respond to ICMP pings.")
            else:
                log_test("ping_cross", f"{target.ip} responds to ICMP pings in {ping_delay} msecs.", level=logger.warning)

    def do_tcp_connect_cross_vlan(self):
        for target in CROSS_VLAN_TARGETS:
            if not target.open_ports:
                continue
            for open_port in target.open_ports:
                status = self.test_tcp(target.ip, open_port, self.router_mac)
                if status == TcpSession.CONNECT_SUCCESS:
                    log_test("tcp_cross", f"{target.ip}:{open_port} accepts TCP connection!", level=logger.warning)
                elif status == TcpSession.CONNECT_TIMEOUT:
                    log_test("tcp_cross", f"{target.ip}:{open_port} time out, no reply.")
                elif status == TcpSession.CONNECT_RESET:
                    log_test("tcp_cross", f"{target.ip}:{open_port} rejects our connection (tcp rst received).")
                else:
                    log_test("tcp_cross", f"{target.ip}:{open_port} unknown error... abnormal...", level=logger.error)

    def do_arp_scan_subnet(self):
        target_network = str(ip_network(self.dhcp_lease.offer.ip_addr_cidr, False))
        clients = self.arp_flood(target_network)

        log_test("arp_scan", f"Found {len(clients)} hosts using simple arp scan of {target_network}.")
        if len(clients) == 0:
            fail("Received no ARP responses. Expected at least a reply for router IP.")

        if self.router_ip not in clients:
            fail("Expected an arp reply for router IP.")

        if clients[self.router_ip] != self.router_mac:
            fail(f"ARP and DHCP mismatch: {self.router_mac} != {clients[self.router_ip]}")

        for ip, mac in clients.items():
            log_test("arp_scan", "{:16}    {}".format(ip, mac))

        return clients

    def arp_flood(self, target_network):
        arp = self.eth_packet(BCAST_MAC) / ARP(psrc=self.src_ip, hwsrc=self.src_mac, pdst=target_network)
        response = srp(arp, timeout=3, iface=self.ifname, verbose=0)
        clients = dict()
        for sent, received in response[0]:
            if received.psrc in clients:
                log_test("arp_scan", f"Received 2 arp replies for same IP address: {received.psrc}", level=logger.warning)
            clients[received.psrc] = received.hwsrc
        return clients

    def do_arp_scan_common_networks(self):
        packets = []
        for ip in ip_network("192.168.0.0/16").hosts():
            if str(ip).endswith(".1"):
                packets.append(self.eth_packet(BCAST_MAC) / ARP(psrc=self.src_ip, pdst=str(ip)))

        responses = self.srp_multi(packets, timeout=5, lfilter=lambda p: p.haslayer(ARP))
        arp_hosts = dict()

        if not responses:
            log_test("arp_flood", "Found nothing.")
            return

        for received in responses:
            if received.psrc in arp_hosts:
                if arp_hosts[received.psrc] != received.hwsrc:
                    log_test("arp_flood", f"Received conflicting arp replies for same IP address: {received.psrc}", level=logger.warning)
            arp_hosts[received.psrc] = received.hwsrc

        for ip, mac in arp_hosts.items():
            log_test("arp_flood", "{:16}    {}".format(ip, mac))

        return arp_hosts

    def do_ping_clients(self, clients):
        for ip, mac in clients.items():
            ping_response, ping_delay = self.send_ping(mac, ip)
            if not ping_response:
                log_test("ping_clients", f"No ping reply from {ip}...", level=logger.warning)
            else:
                log_test("ping_clients", f"Reply from {ip} in {ping_delay} msecs.")

    def send_gratuitous_arp(self):
        arp = ARP(psrc=self.src_ip,
                  hwsrc=self.src_mac,
                  pdst=self.src_ip)
        packet = self.eth_packet(dst=BCAST_MAC) / arp
        self.sendp(packet)

    def do_ping_internet(self, dst_ip):
        ping_response, ping_delay = self.send_ping(self.router_mac, dst_ip)
        if not ping_response:
            log_test("ping_internet", f"Cannot ping internet host {dst_ip} through router {self.router_mac}", level=logger.error)
        else:
            log_test("ping_internet", f"Success: Got reply from {dst_ip} in {ping_delay} msecs.")

    def do_connectivity_check(self, check):
        response_status = self.send_http_get(check.path, host=check.domain, test_name="connectivity")
        if not response_status:
            log_test("connectivity", f"No response from {check.name}", level=logger.error)
        elif response_status != check.expected_status:
            log_test("connectivity", f"Invalid HTTP status from {check.name}: received {response_status}, expected {check.expected_status}", level=logger.error)
        else:
            log_test("connectivity", f"Success checking connectivity with {check.name} ({check.domain}): HTTP {response_status}")

    def send_http_get(self, path, host=None, ip=None, port=80, gw_mac=None, test_name=None):
        if not gw_mac:
            gw_mac = self.router_mac

        if not host and not ip:
            raise ValueError("send_http_get requires either host or ip.")

        if host and ip:
            raise ValueError("send_http_get requires either host or ip, not both.")

        self.send_gratuitous_arp()

        if host:
            ip = socket.gethostbyname(host)
            if not ip:
                log_test(test_name, f"Could not resolve domain {host}", level=logger.error)
                return

        request_lines = list()
        request_lines.append(f"GET {path} HTTP/1.1")
        if host:
            request_lines.append(f"Host: {host}")
        request_lines.append("")
        request_lines.append("")

        request_string = "\r\n".join(request_lines).encode("ascii")

        tcp = TcpSession(self.ifname, self.src_mac, self.src_ip, gw_mac, ip, port)
        connect_status = tcp.connect()
        if connect_status == TcpSession.CONNECT_SUCCESS:
            tcp.send(request_string)
            time.sleep(2)
            packets = tcp.close()

            for p in packets:
                if p.haslayer(HTTP):
                    return int(p[HTTP].Status_Code)

        else:
            log_test(test_name, f"Could not connect to {host}", level=logger.error)

    def do_open_admin_page(self, ip, mac):
        status = self.test_tcp(ip, 80, mac)
        if status == TcpSession.CONNECT_SUCCESS:
            log_test("admin_page", f"{ip}:80 accepts TCP connection! The web status page could be reachable.", level=logger.warning)
        elif status == TcpSession.CONNECT_TIMEOUT:
            log_test("admin_page", f"{ip}:80 time out, no reply.")
        elif status == TcpSession.CONNECT_RESET:
            log_test("admin_page", f"{ip}:80 rejects our connection (tcp rst received).")
        else:
            log_test("admin_page", f"{ip}:80 unknown error... abnormal...", level=logger.error)

    def test_tcp(self, ip, port, gw_mac):
        """
        Attempts to open a TCP connection. Does not send any payload, this only checks if a tcp port is open.
        """
        tcp = TcpSession(self.ifname, self.src_mac, self.src_ip, gw_mac, ip, port)
        connect_status = tcp.connect()
        if connect_status == TcpSession.CONNECT_SUCCESS:
            tcp.close()
        return connect_status

    def srp1_time(self, packet, **kwargs):
        response = self.srp1(packet, **kwargs)
        if response:
            elapsed = response.time - packet.sent_time
            return response, round(elapsed * 1000, 2)
        return response, None

    def srp1(self, packet, timeout=2, lfilter=None, filter=None):
        def started_cb():
            self.sendp(packet)

        sniffer = AsyncSniffer(iface=self.ifname, count=1, timeout=timeout, started_callback=started_cb, filter=filter, lfilter=lfilter)
        sniffer.start()
        sniffer.join()
        if sniffer.results:
            response = sniffer.results[0]
            self.log_in_packet(response)
            return response

    def srp_multi(self, packets, timeout=2, lfilter=None):
        def started_cb():
            for p in packets:
                self.sendp(p)

        sniffer = AsyncSniffer(iface=self.ifname, timeout=timeout, started_callback=started_cb, lfilter=lfilter)
        sniffer.start()
        sniffer.join()
        return sniffer.results

    def sendp(self, packet, **kwargs):
        self.log_out_packet(packet)
        sendp(packet, iface=self.ifname, verbose=0, **kwargs)

    def eth_packet(self, dst):
        return Ether(src=self.src_mac, dst=dst)

    def send_ping(self, dst_mac, dst_ip):
        ping = self.ping_packet(dst_mac, dst_ip)
        ping_id = ping[ICMP].id
        return self.srp1_time(ping, lfilter=lambda p: p.haslayer(ICMP) and p[ICMP].type == 0 and p[ICMP].id == ping_id)

    def ping_packet(self, dst_mac, dst_ip):
        return self.eth_packet(dst_mac) / IP(src=self.src_ip, dst=dst_ip) / ICMP(id=random.randint(1, 65535), type="echo-request")

    def dns_packet(self, dst_mac, dst_ip, qname):
        xid, udp = build_dns_request(qname)
        return xid, self.eth_packet(dst_mac) / IP(src=self.src_ip, dst=dst_ip) / udp

    def log_out_packet(self, packet):
        logger.debug("===> " + str(packet))

    def log_in_packet(self, packet):
        logger.debug("<=== " + str(packet))

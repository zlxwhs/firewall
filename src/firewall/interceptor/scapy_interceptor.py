from scapy.all import AsyncSniffer
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.packet import Packet

from src.common.id_utils import generate_log_id
from datetime import datetime

from src.firewall.logger.log_models import PacketLog
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy_models import PacketPolicy


class ScapyInterceptor:
    def __init__(self, logger: Logger, policy) -> None:
        self.policies = policy.policies
        self.logger = logger
        self.is_running = False
        self.sniffer = AsyncSniffer(prn=self._process_packet, store=False)

    def start(self):
        # 스니퍼 시작
        self.sniffer.start()
        self.is_running = True

    def stop(self):
        # 스니퍼 중지
        self.sniffer.stop()
        self.is_running = False

    def _process_packet(self, packet) -> None:
        # 패킷 요약 정보를 UI에 출력
        packet_log = parse_scapy_packet(packet)
        for policy_name, policy_info in self.policies["packet"].items():
            if matches_packet_policy(packet_log, policy_info):
                packet_log.action = "blocked"
                packet_log.reason = "Blocked by " + policy_info.reason

        self.logger.packet(packet_log)


def parse_scapy_packet(packet: Packet) -> PacketLog:
    timestamp = datetime.fromtimestamp(packet.time).isoformat()

    # 기본값
    protocol = "UNKNOWN"
    src_ip = dst_ip = src_mac = dst_mac = "N/A"
    src_port = dst_port = -1

    if Ether in packet:
        ether = packet[Ether]
        src_mac = ether.src
        dst_mac = ether.dst

    if ARP in packet:
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    elif IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        if TCP in packet:
            protocol = "TCP"
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport

        elif UDP in packet:
            protocol = "UDP"
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        else:
            protocol = ip.proto

    return PacketLog(
        id=generate_log_id(),
        timestamp=timestamp,
        source="scapy",
        action="capture",
        protocol=protocol,
        src_ip=src_ip,
        src_mac=src_mac,
        dst_ip=dst_ip,
        dst_mac=dst_mac,
        src_port=src_port,
        dst_port=dst_port,
        reason="Captured by scapy",
    )


def matches_packet_policy(log: PacketLog, policy: PacketPolicy) -> bool:
    if policy.src_ip is not None and policy.src_ip != log.src_ip:
        return False
    if policy.dst_ip is not None and policy.dst_ip != log.dst_ip:
        return False
    if policy.src_mac is not None and policy.src_mac != log.src_mac:
        return False
    if policy.dst_mac is not None and policy.dst_mac != log.dst_mac:
        return False
    if policy.src_port is not None and policy.src_port != log.src_port:
        return False
    if policy.dst_port is not None and policy.dst_port != log.dst_port:
        return False
    return True

"""Stateless packet forwarder for ServerNIC."""

import logging

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

logger = logging.getLogger("servernic")


class PacketForwarder:
    def __init__(self, client_iface: str = "eth1", server_iface: str = "eth2"):
        self.client_iface = client_iface
        self.server_iface = server_iface

    def handle(self, packet) -> None:
        if not packet.haslayer(TCP):
            return

        ingress = packet.sniffed_on

        if ingress == self.client_iface:
            egress = self.server_iface
            direction = "ClientNIC -> Server"
        elif ingress == self.server_iface:
            egress = self.client_iface
            direction = "Server -> ClientNIC"
        else:
            return

        ip = packet[IP]
        tcp = packet[TCP]
        flags = _tcp_flags(tcp)
        logger.info("%s  %s:%s -> %s:%s [%s]", direction, ip.src, tcp.sport, ip.dst, tcp.dport, flags)

        send(packet[IP], iface=egress, verbose=False)


def _tcp_flags(tcp) -> str:
    parts = []
    if tcp.flags.S:
        parts.append("SYN")
    if tcp.flags.A:
        parts.append("ACK")
    if tcp.flags.P:
        parts.append("PSH")
    if tcp.flags.F:
        parts.append("FIN")
    if tcp.flags.R:
        parts.append("RST")
    return "-".join(parts) if parts else "NONE"

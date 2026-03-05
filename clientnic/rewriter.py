"""Packet rewriting and forwarding."""

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send


class PacketRewriter:
    """Handles packet modification and forwarding."""

    def forward_packet(self, packet: Packet, iface: str) -> None:
        """Forward packet to specified interface (Layer 3)."""
        # Use send() instead of sendp() to let kernel handle L2 headers
        # Kernel will look up routing table and ARP cache for correct MACs
        send(packet[IP], iface=iface, verbose=False)

    def rewrite_client_to_server(self, packet: Packet, delta: int, iface: str) -> None:
        """Rewrite client→server packet: add delta to SEQ, recalculate checksums, forward."""
        pkt = packet[IP].copy()
        pkt[TCP].seq = (pkt[TCP].seq + delta) & 0xFFFFFFFF
        del pkt[IP].chksum
        del pkt[TCP].chksum
        send(pkt, iface=iface, verbose=False)

    def rewrite_server_to_client(self, packet: Packet, delta: int, iface: str) -> None:
        """Rewrite server→client packet: subtract delta from ACK, recalculate checksums, forward."""
        pkt = packet[IP].copy()
        pkt[TCP].ack = (pkt[TCP].ack - delta) & 0xFFFFFFFF
        del pkt[IP].chksum
        del pkt[TCP].chksum
        send(pkt, iface=iface, verbose=False)

    def _recalc_checksums(self, packet: Packet) -> None:
        """Delete checksums to force Scapy recalculation on send."""
        del packet[IP].chksum
        del packet[TCP].chksum

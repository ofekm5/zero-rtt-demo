"""Packet rewriting and forwarding."""

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp


class PacketRewriter:
    """Handles packet modification and forwarding."""

    def forward_packet(self, packet: Packet, iface: str) -> None:
        """Forward packet to specified interface."""
        sendp(packet, iface=iface, verbose=False)

    def _recalc_checksums(self, packet: Packet) -> None:
        """Delete checksums to force Scapy recalculation on send."""
        del packet[IP].chksum
        del packet[TCP].chksum

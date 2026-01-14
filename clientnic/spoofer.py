"""Spoofed SYN-ACK packet creation."""

import random

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


class SynAckSpoofer:
    """Creates spoofed SYN-ACK packets."""

    def create_syn_ack(self, syn_packet: Packet, spoofed_isn: int) -> Packet:
        """Create a spoofed SYN-ACK response to a SYN packet."""
        syn_ack = (
            Ether(src=syn_packet[Ether].dst, dst=syn_packet[Ether].src)
            / IP(src=syn_packet[IP].dst, dst=syn_packet[IP].src)
            / TCP(
                sport=syn_packet[TCP].dport,
                dport=syn_packet[TCP].sport,
                seq=spoofed_isn,
                ack=syn_packet[TCP].seq + 1,
                flags="SA",
            )
        )
        return syn_ack

    @staticmethod
    def generate_random_isn() -> int:
        """Generate a random initial sequence number."""
        return random.randint(0, 0xFFFFFFFF)

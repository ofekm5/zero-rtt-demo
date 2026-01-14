"""Packet handlers for ClientNIC."""

import logging
import threading
from typing import Dict, List

from scapy.packet import Packet
from scapy.layers.inet import TCP

from .flow_table import FlowKey, FlowTable
from .spoofer import SynAckSpoofer
from .rewriter import PacketRewriter


logger = logging.getLogger("clientnic")


class PacketBuffer:
    """Thread-safe buffer for packets awaiting delta calculation."""

    def __init__(self):
        self._buffers: Dict[FlowKey, List[Packet]] = {}
        self._lock = threading.Lock()

    def add(self, key: FlowKey, packet: Packet) -> None:
        """Add packet to buffer for given flow."""
        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = []
            self._buffers[key].append(packet)

    def flush(self, key: FlowKey) -> List[Packet]:
        """Remove and return all buffered packets for given flow."""
        with self._lock:
            return self._buffers.pop(key, [])


class ClientPacketHandler:
    """Handles packets from client (eth0)."""

    def __init__(
        self,
        flow_table: FlowTable,
        spoofer: SynAckSpoofer,
        rewriter: PacketRewriter,
        buffer: PacketBuffer,
        client_iface: str = "eth0",
        server_iface: str = "eth1",
    ):
        self._flow_table = flow_table
        self._spoofer = spoofer
        self._rewriter = rewriter
        self._buffer = buffer
        self._client_iface = client_iface
        self._server_iface = server_iface

    def handle(self, packet: Packet) -> None:
        """Process a packet from the client."""
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]

        if self._is_syn(tcp):
            self._handle_syn(packet)
        else:
            self._handle_data(packet)

    def _is_syn(self, tcp: TCP) -> bool:
        """Check if packet is a SYN (not SYN-ACK)."""
        return tcp.flags.S and not tcp.flags.A

    def _handle_syn(self, packet: Packet) -> None:
        """Handle SYN packet: create flow, send spoofed SYN-ACK, forward SYN."""
        key = FlowTable.extract_key(packet)
        spoofed_isn = self._spoofer.generate_random_isn()

        # Create flow entry
        self._flow_table.create_flow(key, packet[TCP].seq, spoofed_isn)
        logger.info(f"SYN received, flow created: {key}")

        # Send spoofed SYN-ACK to client
        syn_ack = self._spoofer.create_syn_ack(packet, spoofed_isn)
        self._rewriter.forward_packet(syn_ack, self._client_iface)
        logger.info(f"Spoofed SYN-ACK sent to client")

        # Forward original SYN to server
        self._rewriter.forward_packet(packet, self._server_iface)
        logger.info(f"Original SYN forwarded to server")

    def _handle_data(self, packet: Packet) -> None:
        """Handle ACK/DATA packet: buffer until delta is known."""
        key = FlowTable.extract_key(packet)
        self._buffer.add(key, packet)
        logger.debug(f"Packet buffered for flow: {key}")

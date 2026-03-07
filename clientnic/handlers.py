"""Packet handlers for ClientNIC."""

import logging
import threading
from typing import Dict, List

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP

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
        """Handle ACK/DATA packet: forward with seq rewrite if delta known, otherwise buffer."""
        key = FlowTable.extract_key(packet)
        entry = self._flow_table.get_flow(key)
        if entry is not None and entry.seq_delta is not None:
            self._rewriter.rewrite_client_to_server(packet, entry.seq_delta, self._server_iface)
            logger.debug(f"Packet forwarded with seq rewrite for flow: {key}")
        else:
            self._buffer.add(key, packet)
            logger.debug(f"Packet buffered for flow: {key}")


class ServerPacketHandler:
    """Handles packets from server/ServerNIC (eth1)."""

    def __init__(
        self,
        flow_table: FlowTable,
        rewriter: PacketRewriter,
        buffer: PacketBuffer,
        client_iface: str = "eth0",
        server_iface: str = "eth1",
    ):
        self._flow_table = flow_table
        self._rewriter = rewriter
        self._buffer = buffer
        self._client_iface = client_iface
        self._server_iface = server_iface

    def handle(self, packet: Packet) -> None:
        """Process a packet from the server."""
        if not packet.haslayer(TCP):
            return

        # eth1 sniffs all TCP on the interface, including packets ClientNIC itself
        # sent out (forwarded SYN, client ACKs, etc.). These outgoing packets have a
        # forward flow key (client src → server dst) that exists in the flow table.
        # Skip them — only process incoming server→client packets.
        forward_key = FlowTable.extract_key(packet)
        if self._flow_table.get_flow(forward_key) is not None:
            return

        tcp = packet[TCP]

        if self._is_syn_ack(tcp):
            self._handle_syn_ack(packet)
        else:
            self._handle_data(packet)

    def _is_syn_ack(self, tcp: TCP) -> bool:
        return tcp.flags.S and tcp.flags.A

    def _handle_syn_ack(self, packet: Packet) -> None:
        """Handle real SYN-ACK: compute delta, flush buffered packets, drop the SYN-ACK."""
        # Reverse src/dst to match the flow key stored when the client's SYN was seen
        reverse_key = FlowKey(
            src_ip=packet[IP].dst,
            src_port=packet[TCP].dport,
            dst_ip=packet[IP].src,
            dst_port=packet[TCP].sport,
        )
        real_server_isn = packet[TCP].seq
        delta = self._flow_table.set_delta(reverse_key, real_server_isn)
        if delta is None:
            logger.warning(f"Real SYN-ACK for unknown flow: {reverse_key}")
            return

        logger.info(f"Real SYN-ACK received, delta={delta} for flow: {reverse_key}")

        # Drop the real SYN-ACK — client already received the spoofed one
        # Flush any client packets buffered while waiting for delta
        buffered = self._buffer.flush(reverse_key)
        for pkt in buffered:
            self._rewriter.rewrite_client_to_server(pkt, delta, self._server_iface)
        if buffered:
            logger.info(f"Flushed {len(buffered)} buffered packets for flow: {reverse_key}")

    def _handle_data(self, packet: Packet) -> None:
        """Handle server→client data: subtract delta from ACK, forward to client."""
        reverse_key = FlowKey(
            src_ip=packet[IP].dst,
            src_port=packet[TCP].dport,
            dst_ip=packet[IP].src,
            dst_port=packet[TCP].sport,
        )
        entry = self._flow_table.get_flow(reverse_key)
        if entry is None or entry.seq_delta is None:
            logger.warning(f"Data from server for unknown/unready flow: {reverse_key}")
            return

        self._rewriter.rewrite_server_to_client(packet, entry.seq_delta, self._client_iface)
        logger.debug(f"Server->client packet forwarded with ack rewrite for flow: {reverse_key}")

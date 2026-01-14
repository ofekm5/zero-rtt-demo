"""Flow table for tracking TCP connections and sequence number state."""

import threading
from dataclasses import dataclass
from typing import Dict, Optional

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP


@dataclass(frozen=True)
class FlowKey:
    """4-tuple connection identifier."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass
class FlowEntry:
    """Connection state for a single flow."""
    client_isn: int
    spoofed_server_isn: int
    state: str = "SYN_SENT"


class FlowTable:
    """Thread-safe flow table for tracking connections."""

    def __init__(self):
        self._flows: Dict[FlowKey, FlowEntry] = {}
        self._lock = threading.Lock()

    def create_flow(self, key: FlowKey, client_isn: int, spoofed_isn: int) -> FlowEntry:
        """Create a new flow entry."""
        entry = FlowEntry(client_isn=client_isn, spoofed_server_isn=spoofed_isn)
        with self._lock:
            self._flows[key] = entry
        return entry

    def get_flow(self, key: FlowKey) -> Optional[FlowEntry]:
        """Get flow entry by key."""
        with self._lock:
            return self._flows.get(key)

    @staticmethod
    def extract_key(packet: Packet) -> FlowKey:
        """Extract FlowKey from a packet."""
        return FlowKey(
            src_ip=packet[IP].src,
            src_port=packet[TCP].sport,
            dst_ip=packet[IP].dst,
            dst_port=packet[TCP].dport,
        )

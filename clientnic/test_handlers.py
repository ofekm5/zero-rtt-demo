"""Unit tests for handlers.py"""

import pytest
from unittest.mock import MagicMock, patch
import threading

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from clientnic.handlers import PacketBuffer, ClientPacketHandler
from clientnic.flow_table import FlowKey, FlowTable


class TestPacketBuffer:
    """Tests for PacketBuffer class."""

    def test_add_single_packet(self):
        """Test adding a single packet to buffer."""
        buffer = PacketBuffer()
        key = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)
        mock_packet = MagicMock()

        buffer.add(key, mock_packet)
        packets = buffer.flush(key)

        assert len(packets) == 1
        assert packets[0] is mock_packet

    def test_add_multiple_packets_same_flow(self):
        """Test adding multiple packets to same flow."""
        buffer = PacketBuffer()
        key = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)
        packets_in = [MagicMock() for _ in range(5)]

        for pkt in packets_in:
            buffer.add(key, pkt)

        packets_out = buffer.flush(key)

        assert len(packets_out) == 5
        assert packets_out == packets_in

    def test_flush_removes_packets(self):
        """Test flush removes packets from buffer."""
        buffer = PacketBuffer()
        key = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)
        buffer.add(key, MagicMock())

        buffer.flush(key)
        packets = buffer.flush(key)

        assert packets == []

    def test_flush_nonexistent_key(self):
        """Test flush returns empty list for unknown key."""
        buffer = PacketBuffer()
        key = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)

        packets = buffer.flush(key)

        assert packets == []

    def test_multiple_flows_isolated(self):
        """Test different flows are isolated."""
        buffer = PacketBuffer()
        key1 = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)
        key2 = FlowKey("1.1.1.1", 101, "2.2.2.2", 80)
        pkt1 = MagicMock()
        pkt2 = MagicMock()

        buffer.add(key1, pkt1)
        buffer.add(key2, pkt2)

        packets1 = buffer.flush(key1)
        packets2 = buffer.flush(key2)

        assert packets1 == [pkt1]
        assert packets2 == [pkt2]

    def test_thread_safety(self):
        """Test concurrent access to buffer."""
        buffer = PacketBuffer()
        key = FlowKey("1.1.1.1", 100, "2.2.2.2", 80)

        def add_packets():
            for _ in range(100):
                buffer.add(key, MagicMock())

        threads = [threading.Thread(target=add_packets) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        packets = buffer.flush(key)
        assert len(packets) == 300


class TestClientPacketHandler:
    """Tests for ClientPacketHandler class."""

    @pytest.fixture
    def handler_setup(self):
        """Create handler with mocked dependencies."""
        flow_table = FlowTable()
        spoofer = MagicMock()
        rewriter = MagicMock()
        buffer = PacketBuffer()

        spoofer.generate_random_isn.return_value = 5000
        spoofer.create_syn_ack.return_value = MagicMock()

        handler = ClientPacketHandler(
            flow_table=flow_table,
            spoofer=spoofer,
            rewriter=rewriter,
            buffer=buffer,
            client_iface="eth0",
            server_iface="eth1",
        )
        return handler, flow_table, spoofer, rewriter, buffer

    def test_handle_ignores_non_tcp(self, handler_setup):
        """Test non-TCP packets are ignored."""
        handler, _, _, rewriter, _ = handler_setup

        # Packet without TCP layer
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False

        handler.handle(mock_packet)

        rewriter.forward_packet.assert_not_called()

    def test_is_syn_true(self, handler_setup):
        """Test _is_syn correctly identifies SYN packets."""
        handler, _, _, _, _ = handler_setup

        mock_tcp = MagicMock()
        mock_tcp.flags.S = True
        mock_tcp.flags.A = False

        assert handler._is_syn(mock_tcp) is True

    def test_is_syn_false_for_syn_ack(self, handler_setup):
        """Test _is_syn returns False for SYN-ACK."""
        handler, _, _, _, _ = handler_setup

        mock_tcp = MagicMock()
        mock_tcp.flags.S = True
        mock_tcp.flags.A = True

        assert handler._is_syn(mock_tcp) is False

    def test_is_syn_false_for_ack(self, handler_setup):
        """Test _is_syn returns False for ACK."""
        handler, _, _, _, _ = handler_setup

        mock_tcp = MagicMock()
        mock_tcp.flags.S = False
        mock_tcp.flags.A = True

        assert handler._is_syn(mock_tcp) is False

    def test_handle_syn_creates_flow(self, handler_setup):
        """Test SYN packet creates flow entry."""
        handler, flow_table, spoofer, _, _ = handler_setup

        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=1000, flags="S")
        )

        handler.handle(syn)

        key = FlowKey("192.168.1.1", 12345, "10.0.0.1", 80)
        entry = flow_table.get_flow(key)

        assert entry is not None
        assert entry.client_isn == 1000
        assert entry.spoofed_server_isn == 5000

    def test_handle_syn_sends_spoofed_syn_ack(self, handler_setup):
        """Test SYN packet triggers spoofed SYN-ACK to client."""
        handler, _, spoofer, rewriter, _ = handler_setup

        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=1000, flags="S")
        )

        handler.handle(syn)

        spoofer.create_syn_ack.assert_called_once()
        # First forward call is SYN-ACK to client on eth0
        calls = rewriter.forward_packet.call_args_list
        assert len(calls) == 2
        assert calls[0][0][1] == "eth0"  # SYN-ACK to client

    def test_handle_syn_forwards_to_server(self, handler_setup):
        """Test SYN packet is forwarded to server."""
        handler, _, _, rewriter, _ = handler_setup

        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=1000, flags="S")
        )

        handler.handle(syn)

        # Second forward call is original SYN to server on eth1
        calls = rewriter.forward_packet.call_args_list
        assert calls[1][0][1] == "eth1"

    def test_handle_data_buffers_packet(self, handler_setup):
        """Test ACK/DATA packets are buffered."""
        handler, _, _, _, buffer = handler_setup

        ack = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        )

        handler.handle(ack)

        key = FlowKey("192.168.1.1", 12345, "10.0.0.1", 80)
        packets = buffer.flush(key)
        assert len(packets) == 1


class TestClientPacketHandlerEdgeCases:
    """Edge case tests for ClientPacketHandler."""

    def test_handle_multiple_syns_same_flow(self):
        """Test multiple SYNs for same flow overwrites entry."""
        flow_table = FlowTable()
        spoofer = MagicMock()
        spoofer.generate_random_isn.side_effect = [1000, 2000]
        spoofer.create_syn_ack.return_value = MagicMock()

        handler = ClientPacketHandler(
            flow_table=flow_table,
            spoofer=spoofer,
            rewriter=MagicMock(),
            buffer=PacketBuffer(),
        )

        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=100, flags="S")
        )

        handler.handle(syn)
        handler.handle(syn)

        key = FlowKey("192.168.1.1", 12345, "10.0.0.1", 80)
        entry = flow_table.get_flow(key)
        assert entry.spoofed_server_isn == 2000  # Second ISN

"""Unit tests for rewriter.py"""

import pytest
from unittest.mock import MagicMock, patch

from scapy.layers.inet import IP, TCP

from clientnic.rewriter import PacketRewriter


class TestPacketRewriter:
    """Tests for PacketRewriter class."""

    @patch('clientnic.rewriter.sendp')
    def test_forward_packet(self, mock_sendp):
        """Test packet forwarding calls sendp correctly."""
        rewriter = PacketRewriter()
        mock_packet = MagicMock()

        rewriter.forward_packet(mock_packet, "eth0")

        mock_sendp.assert_called_once_with(mock_packet, iface="eth0", verbose=False)

    @patch('clientnic.rewriter.sendp')
    def test_forward_packet_different_interface(self, mock_sendp):
        """Test forwarding to different interface."""
        rewriter = PacketRewriter()
        mock_packet = MagicMock()

        rewriter.forward_packet(mock_packet, "eth1")

        mock_sendp.assert_called_once_with(mock_packet, iface="eth1", verbose=False)

    def test_recalc_checksums(self):
        """Test checksum fields are deleted for recalculation."""
        rewriter = PacketRewriter()

        # Create a real packet with checksums
        packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80)

        # Set checksums to known values
        packet[IP].chksum = 0x1234
        packet[TCP].chksum = 0x5678

        rewriter._recalc_checksums(packet)

        # After deletion, checksums should be None (will be recalculated on send)
        assert packet[IP].chksum is None
        assert packet[TCP].chksum is None


class TestPacketRewriterEdgeCases:
    """Edge case tests for PacketRewriter."""

    @patch('clientnic.rewriter.sendp')
    def test_forward_multiple_packets(self, mock_sendp):
        """Test forwarding multiple packets."""
        rewriter = PacketRewriter()
        packets = [MagicMock() for _ in range(3)]

        for i, pkt in enumerate(packets):
            rewriter.forward_packet(pkt, f"eth{i % 2}")

        assert mock_sendp.call_count == 3

    @patch('clientnic.rewriter.sendp')
    def test_forward_packet_verbose_disabled(self, mock_sendp):
        """Verify verbose is always False to avoid console spam."""
        rewriter = PacketRewriter()
        mock_packet = MagicMock()

        rewriter.forward_packet(mock_packet, "eth0")

        _, kwargs = mock_sendp.call_args
        assert kwargs['verbose'] == False

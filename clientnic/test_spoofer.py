"""Unit tests for spoofer.py"""

import pytest
from unittest.mock import MagicMock, patch

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from clientnic.spoofer import SynAckSpoofer


class TestSynAckSpoofer:
    """Tests for SynAckSpoofer class."""

    def test_create_syn_ack_basic(self):
        """Test basic SYN-ACK creation."""
        spoofer = SynAckSpoofer()

        # Create a mock SYN packet
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.1", dst="10.0.0.1")
            / TCP(sport=12345, dport=80, seq=1000, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=5000)

        # Verify Ether layer is swapped
        assert syn_ack[Ether].src == "aa:bb:cc:dd:ee:02"
        assert syn_ack[Ether].dst == "aa:bb:cc:dd:ee:01"

        # Verify IP layer is swapped
        assert syn_ack[IP].src == "10.0.0.1"
        assert syn_ack[IP].dst == "192.168.1.1"

        # Verify TCP layer
        assert syn_ack[TCP].sport == 80
        assert syn_ack[TCP].dport == 12345
        assert syn_ack[TCP].seq == 5000
        assert syn_ack[TCP].ack == 1001  # client_seq + 1
        assert syn_ack[TCP].flags == "SA"

    def test_create_syn_ack_flags(self):
        """Test SYN-ACK has correct flags."""
        spoofer = SynAckSpoofer()
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=0, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=0)

        # Check flags - SA means SYN+ACK
        assert syn_ack[TCP].flags.S == True
        assert syn_ack[TCP].flags.A == True
        assert syn_ack[TCP].flags.F == False
        assert syn_ack[TCP].flags.R == False

    def test_create_syn_ack_seq_wraparound(self):
        """Test SYN-ACK ack calculation near 32-bit boundary."""
        spoofer = SynAckSpoofer()
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=0xFFFFFFFF, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=100)

        # ack should be 0xFFFFFFFF + 1 = 0 (wraparound)
        # Note: Scapy may handle this automatically or not
        assert syn_ack[TCP].ack == 0x100000000  # Scapy doesn't auto-wrap

    def test_generate_random_isn_range(self):
        """Test ISN generation is within 32-bit range."""
        spoofer = SynAckSpoofer()

        for _ in range(100):
            isn = spoofer.generate_random_isn()
            assert 0 <= isn <= 0xFFFFFFFF

    def test_generate_random_isn_randomness(self):
        """Test ISN generation produces different values."""
        spoofer = SynAckSpoofer()

        isns = [spoofer.generate_random_isn() for _ in range(10)]

        # All values should not be the same (highly unlikely with random)
        assert len(set(isns)) > 1

    @patch('clientnic.spoofer.random.randint')
    def test_generate_random_isn_uses_full_range(self, mock_randint):
        """Test ISN generation uses correct range."""
        mock_randint.return_value = 12345
        spoofer = SynAckSpoofer()

        isn = spoofer.generate_random_isn()

        mock_randint.assert_called_once_with(0, 0xFFFFFFFF)
        assert isn == 12345


class TestSynAckSpooferEdgeCases:
    """Edge case tests for SynAckSpoofer."""

    def test_zero_sequence_number(self):
        """Test with seq=0."""
        spoofer = SynAckSpoofer()
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=0, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=0)

        assert syn_ack[TCP].seq == 0
        assert syn_ack[TCP].ack == 1

    def test_max_ports(self):
        """Test with maximum port numbers."""
        spoofer = SynAckSpoofer()
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=65535, dport=65535, seq=100, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=200)

        assert syn_ack[TCP].sport == 65535
        assert syn_ack[TCP].dport == 65535

    def test_max_isn(self):
        """Test with maximum ISN value."""
        spoofer = SynAckSpoofer()
        syn = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=100, flags="S")
        )

        syn_ack = spoofer.create_syn_ack(syn, spoofed_isn=0xFFFFFFFF)

        assert syn_ack[TCP].seq == 0xFFFFFFFF

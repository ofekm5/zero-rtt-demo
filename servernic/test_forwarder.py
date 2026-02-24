"""Unit tests for PacketForwarder."""

from unittest.mock import patch, MagicMock

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from servernic.forwarder import PacketForwarder


def _make_packet(sniffed_on: str, has_tcp: bool = True):
    pkt = Ether() / IP(src="10.1.0.1", dst="10.1.2.1") / TCP(sport=12345, dport=8080, flags="S")
    if not has_tcp:
        pkt = Ether() / IP(src="10.1.0.1", dst="10.1.2.1")
    pkt.sniffed_on = sniffed_on
    return pkt


@patch("servernic.forwarder.send")
def test_handle_forwards_from_client_to_server(mock_send):
    fwd = PacketForwarder(client_iface="eth1", server_iface="eth2")
    pkt = _make_packet(sniffed_on="eth1")
    fwd.handle(pkt)
    mock_send.assert_called_once()
    _, kwargs = mock_send.call_args
    assert kwargs["iface"] == "eth2"


@patch("servernic.forwarder.send")
def test_handle_forwards_from_server_to_client(mock_send):
    fwd = PacketForwarder(client_iface="eth1", server_iface="eth2")
    pkt = _make_packet(sniffed_on="eth2")
    fwd.handle(pkt)
    mock_send.assert_called_once()
    _, kwargs = mock_send.call_args
    assert kwargs["iface"] == "eth1"


@patch("servernic.forwarder.send")
def test_handle_ignores_non_tcp(mock_send):
    fwd = PacketForwarder()
    pkt = _make_packet(sniffed_on="eth1", has_tcp=False)
    fwd.handle(pkt)
    mock_send.assert_not_called()


@patch("servernic.forwarder.send")
def test_handle_unknown_interface(mock_send):
    fwd = PacketForwarder(client_iface="eth1", server_iface="eth2")
    pkt = _make_packet(sniffed_on="eth0")
    fwd.handle(pkt)
    mock_send.assert_not_called()


@patch("servernic.forwarder.send")
def test_custom_interface_names(mock_send):
    fwd = PacketForwarder(client_iface="ens5", server_iface="ens6")
    pkt = _make_packet(sniffed_on="ens5")
    fwd.handle(pkt)
    mock_send.assert_called_once()
    _, kwargs = mock_send.call_args
    assert kwargs["iface"] == "ens6"

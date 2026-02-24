"""ServerNIC entry point."""

import argparse
import logging

from scapy.sendrecv import sniff

from .logger import setup_logging
from .forwarder import PacketForwarder


def main():
    parser = argparse.ArgumentParser(description="ServerNIC - stateless packet forwarder")
    parser.add_argument("--client-iface", default="eth1", help="Interface facing ClientNIC (default: eth1)")
    parser.add_argument("--server-iface", default="eth2", help="Interface facing Server (default: eth2)")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    logger = setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    logger.info("Starting ServerNIC...")
    logger.info("Forwarding between %s (ClientNIC) <-> %s (Server)", args.client_iface, args.server_iface)

    forwarder = PacketForwarder(client_iface=args.client_iface, server_iface=args.server_iface)

    sniff(
        iface=[args.client_iface, args.server_iface],
        prn=forwarder.handle,
        filter="tcp",
        store=False,
    )


if __name__ == "__main__":
    main()

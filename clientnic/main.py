"""ClientNIC entry point."""

import threading

from scapy.sendrecv import sniff

from .logger import setup_logging
from .flow_table import FlowTable
from .spoofer import SynAckSpoofer
from .rewriter import PacketRewriter
from .handlers import PacketBuffer, ClientPacketHandler, ServerPacketHandler


def main():
    """Start ClientNIC packet capture and processing."""
    logger = setup_logging()
    logger.info("Starting ClientNIC...")

    # Create shared instances
    flow_table = FlowTable()
    spoofer = SynAckSpoofer()
    rewriter = PacketRewriter()
    buffer = PacketBuffer()

    # Create handlers
    client_handler = ClientPacketHandler(
        flow_table=flow_table,
        spoofer=spoofer,
        rewriter=rewriter,
        buffer=buffer,
    )
    server_handler = ServerPacketHandler(
        flow_table=flow_table,
        rewriter=rewriter,
        buffer=buffer,
    )

    # Sniff eth1 (server-side) in background thread
    logger.info("Sniffing on eth1...")
    eth1_thread = threading.Thread(
        target=sniff,
        kwargs=dict(iface="eth1", prn=server_handler.handle, filter="tcp", store=False),
        daemon=True,
    )
    eth1_thread.start()

    # Sniff eth0 (client-side) in main thread
    logger.info("Sniffing on eth0...")
    sniff(
        iface="eth0",
        prn=client_handler.handle,
        filter="tcp",
        store=False,
    )


if __name__ == "__main__":
    main()

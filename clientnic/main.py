"""ClientNIC entry point."""

from scapy.sendrecv import sniff

from .logger import setup_logging
from .flow_table import FlowTable
from .spoofer import SynAckSpoofer
from .rewriter import PacketRewriter
from .handlers import PacketBuffer, ClientPacketHandler


def main():
    """Start ClientNIC packet capture and processing."""
    logger = setup_logging()
    logger.info("Starting ClientNIC...")

    # Create shared instances
    flow_table = FlowTable()
    spoofer = SynAckSpoofer()
    rewriter = PacketRewriter()
    buffer = PacketBuffer()

    # Create handler
    client_handler = ClientPacketHandler(
        flow_table=flow_table,
        spoofer=spoofer,
        rewriter=rewriter,
        buffer=buffer,
    )

    logger.info("Sniffing on eth0...")
    sniff(
        iface="eth0",
        prn=client_handler.handle,
        filter="tcp",
        store=False,
    )


if __name__ == "__main__":
    main()

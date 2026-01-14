# ClientNIC

0-RTT TCP middleware that intercepts SYN packets and sends spoofed SYN-ACK responses.

## Requirements

- Python 3.8+
- Scapy (`pip install scapy`)
- Root privileges (for raw sockets)
- Linux with eth0/eth1 interfaces

## Usage

```bash
sudo python -m clientnic.main
```

## Current Functionality (Phase 1)

**Client -> Server (eth0):**
- SYN → creates flow entry, sends spoofed SYN-ACK to client, forwards original SYN to eth1
- ACK/DATA → buffered (delta calculation not yet implemented)

## Architecture

```
clientnic/
├── main.py          # Entry point, wires dependencies
├── handlers.py      # ClientPacketHandler, PacketBuffer
├── flow_table.py    # FlowKey, FlowEntry, FlowTable
├── rewriter.py      # PacketRewriter (forwarding)
├── spoofer.py       # SynAckSpoofer
└── logger.py        # Logging setup
```

## Testing

Use tcpdump to verify:
```bash
# Terminal 1: Run ClientNIC
sudo python -m clientnic.main

# Terminal 2: Watch eth0
sudo tcpdump -i eth0 tcp -nn

# Terminal 3: Send SYN
sudo hping3 -S -p 80 <dest_ip>
```

Expected: SYN-ACK response appears immediately on eth0.

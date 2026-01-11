# ServerNIC VM - Detailed Design

## Overview
The ServerNIC VM is a simple packet forwarding component that sits between the ClientNIC and the actual Server. Its primary role is to transparently forward packets in both directions without modification, acting as a network bridge.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  ServerNIC VM                                               │
│                                                             │
│  ┌─────────────┐                        ┌─────────────┐     │
│  │ sniffer     │───────────────────────▶│ forwarder   │     │
│  │             │                        │             │     │
│  │ sniff()     │                        │ sendp()     │     │
│  │ on eth1/2   │                        │ on eth1/2   │     │
│  └─────────────┘                        └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Network Interfaces
- **eth1**: Connected to ClientNIC VM
- **eth2**: Connected to Server VM

## Core Functionality

### 1. Packet Capture and Routing

```python
from scapy.all import sniff, sendp

def start_packet_capture():
    """Start sniffing on both network interfaces"""
    sniff(
        iface=["eth1", "eth2"],
        prn=packet_handler,
        filter="tcp",
        store=False
    )

def packet_handler(packet):
    """Main packet processing logic - simple forwarding"""
    iface = packet.sniff_metadata.get('iface')

    if iface == 'eth1':  # From ClientNIC
        forward_to_server(packet)
    elif iface == 'eth2':  # From Server
        forward_to_client_nic(packet)
```

### 2. Forwarding to Server

All packets from ClientNIC are forwarded directly to the server:

```python
def forward_to_server(packet):
    """Forward packet from ClientNIC to Server"""
    # Log for debugging/demo purposes
    log_packet(packet, direction='ClientNIC -> Server')

    # Forward packet on eth2 (server interface)
    send_packet(packet, interface='eth2')
```

### 3. Forwarding to ClientNIC

All packets from the server are forwarded back to ClientNIC:

```python
def forward_to_client_nic(packet):
    """Forward packet from Server to ClientNIC"""
    # Log for debugging/demo purposes
    log_packet(packet, direction='Server -> ClientNIC')

    # Forward packet on eth1 (ClientNIC interface)
    send_packet(packet, interface='eth1')
```

### 4. Packet Sending

```python
def send_packet(packet, interface):
    """Send packet out on specified interface"""
    sendp(packet, iface=interface, verbose=False)
```

### 5. Logging (Optional)

```python
from scapy.all import TCP, IP

def log_packet(packet, direction):
    """Log packet details for demonstration/debugging"""
    if not packet.haslayer(TCP):
        return

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    flags = get_tcp_flags(tcp_layer)
    seq = tcp_layer.seq
    ack = tcp_layer.ack if tcp_layer.flags.A else None

    log_entry = {
        'timestamp': get_timestamp(),
        'direction': direction,
        'src': f"{ip_layer.src}:{tcp_layer.sport}",
        'dst': f"{ip_layer.dst}:{tcp_layer.dport}",
        'flags': flags,
        'seq': seq,
        'ack': ack,
        'payload_len': len(tcp_layer.payload)
    }

    write_to_log(log_entry)

def get_tcp_flags(tcp_layer):
    """Extract TCP flags as string (e.g., 'SYN', 'ACK', 'PSH-ACK')"""
    flags = []
    if tcp_layer.flags.S: flags.append('SYN')
    if tcp_layer.flags.A: flags.append('ACK')
    if tcp_layer.flags.P: flags.append('PSH')
    if tcp_layer.flags.F: flags.append('FIN')
    if tcp_layer.flags.R: flags.append('RST')
    return '-'.join(flags) if flags else 'NONE'
```

### 6. Main Entry Point

```python
def main():
    """Main entry point for ServerNIC"""
    print("Starting ServerNIC VM...")
    print("Interfaces: eth1 (ClientNIC), eth2 (Server)")

    # Initialize logging
    setup_logging()

    # Start packet capture (blocking)
    start_packet_capture()

if __name__ == "__main__":
    main()
```

## Complete Implementation Example

```python
#!/usr/bin/env python3
from scapy.all import sniff, sendp, TCP, IP
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)

def packet_handler(packet):
    """Route packets between ClientNIC and Server"""
    if not packet.haslayer(TCP):
        return

    iface = packet.sniff_metadata.get('iface')

    if iface == 'eth1':
        # From ClientNIC -> to Server
        logger.info(f"Forwarding to Server: {summarize_packet(packet)}")
        sendp(packet, iface='eth2', verbose=False)

    elif iface == 'eth2':
        # From Server -> to ClientNIC
        logger.info(f"Forwarding to ClientNIC: {summarize_packet(packet)}")
        sendp(packet, iface='eth1', verbose=False)

def summarize_packet(packet):
    """Create human-readable packet summary"""
    ip = packet[IP]
    tcp = packet[TCP]
    flags = get_tcp_flags_str(tcp)

    return f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} [{flags}] seq={tcp.seq}"

def get_tcp_flags_str(tcp_layer):
    """Get TCP flags as string"""
    flags = []
    if tcp_layer.flags.S: flags.append('SYN')
    if tcp_layer.flags.A: flags.append('ACK')
    if tcp_layer.flags.P: flags.append('PSH')
    if tcp_layer.flags.F: flags.append('FIN')
    return '-'.join(flags) if flags else ''

def main():
    logger.info("ServerNIC starting...")
    logger.info("Forwarding between eth1 (ClientNIC) <-> eth2 (Server)")

    # Start packet capture
    sniff(
        iface=["eth1", "eth2"],
        prn=packet_handler,
        filter="tcp",
        store=False
    )

if __name__ == "__main__":
    main()
```

## Key Design Decisions

1. **Stateless Operation**: Unlike ClientNIC, ServerNIC maintains no connection state. It simply forwards packets based on which interface they arrive on.

2. **No Packet Modification**: Packets are forwarded as-is without any sequence number rewriting or checksum recalculation.

3. **Transparent Forwarding**: From the server's perspective, packets appear to come directly from the client (after ClientNIC's rewriting).

4. **Optional Logging**: Logging is included for demonstration and debugging purposes but can be disabled in production.

## Module Structure

```
server_nic/
├── main.py              # Entry point, simple packet forwarding
└── logger.py            # Log packets for demo proof (optional)
```

## Why ServerNIC Exists

The ServerNIC VM serves several purposes:

1. **Network Isolation**: Separates the ClientNIC's manipulation logic from the actual server, preventing any accidental interference.

2. **Modularity**: Keeps the 0-RTT logic contained in ClientNIC, making it easier to test and debug.

3. **Real-world Simulation**: In a real network scenario, packets would traverse multiple hops. This simulates that realistic topology.

4. **Future Extensions**: Provides a clean insertion point for server-side optimizations or monitoring without affecting ClientNIC logic.

## Performance Considerations

- Minimal processing overhead (simple forwarding)
- No flow table or state management required
- Can handle high packet rates with low latency
- Scapy's `sendp()` is used for fast packet transmission

## Testing Considerations

- Verify bidirectional forwarding works correctly
- Ensure packets are not modified during forwarding
- Test with high packet rates
- Verify logging doesn't impact performance
- Test interface failover scenarios

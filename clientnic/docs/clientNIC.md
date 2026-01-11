# ClientNIC VM - Detailed Design

## Overview
The ClientNIC VM is the core component that implements the 0-RTT TCP optimization. It sits between the client and the ServerNIC, intercepting TCP handshakes and enabling clients to send data immediately without waiting for the full 3-way handshake to complete.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  ClientNIC VM                                               │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ sniffer     │───▶│ flow_table  │───▶│ forwarder   │     │
│  │             │    │             │    │             │     │
│  │ sniff()     │    │ track state │    │ sendp()     │     │
│  │ on eth0/1   │    │ seq deltas  │    │ on eth0/1   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Network Interfaces
- **eth0**: Connected to Client VM
- **eth1**: Connected to ServerNIC VM

## Core Functionality

### 1. Packet Capture and Routing

```python
from scapy.all import sniff, TCP, IP

def start_packet_capture():
    """Start sniffing on both network interfaces"""
    sniff(
        iface=["eth0", "eth1"],
        prn=packet_handler,
        filter="tcp",
        store=False
    )

def packet_handler(packet):
    """Main packet processing logic"""
    if not packet.haslayer(TCP):
        return

    iface = packet.sniff_metadata.get('iface')

    if iface == 'eth0':  # From client
        handle_client_packet(packet)
    elif iface == 'eth1':  # From ServerNIC
        handle_server_packet(packet)
```

### 2. SYN Packet Handling (0-RTT Optimization)

When a SYN packet arrives from the client, the ClientNIC performs two actions:
1. Immediately sends a spoofed SYN-ACK to the client
2. Forwards the original SYN to the ServerNIC

```python
def handle_client_packet(packet):
    """Process packets from client"""
    tcp_layer = packet[TCP]

    if is_syn_packet(tcp_layer):
        # Create flow entry to track this connection
        flow = create_flow_entry(packet)

        # Generate and send spoofed SYN-ACK immediately
        syn_ack = craft_spoofed_syn_ack(packet, flow)
        send_to_interface(syn_ack, interface='eth0')

        # Forward original SYN to ServerNIC
        forward_packet(packet, interface='eth1')

        log_event(f"SYN intercepted, spoofed SYN-ACK sent to client")

    elif is_ack_or_data_packet(tcp_layer):
        # Client is sending ACK or DATA (possibly before real handshake completes)
        handle_client_data(packet)
```

### 3. Flow Table Management

The flow table tracks connection state and sequence number deltas:

```python
class FlowTable:
    def __init__(self):
        self.flows = {}

    def create_flow(self, syn_packet):
        """Create a new flow entry for a SYN packet"""
        key = extract_flow_key(syn_packet)

        flow_entry = {
            'client_isn': syn_packet[TCP].seq,
            'spoofed_server_isn': generate_random_seq(),
            'real_server_isn': None,
            'seq_delta': None,
            'state': 'SYN_SENT'
        }

        self.flows[key] = flow_entry
        return flow_entry

    def update_with_real_syn_ack(self, syn_ack_packet):
        """Update flow when real SYN-ACK arrives from server"""
        key = extract_flow_key(syn_ack_packet)
        flow = self.flows[key]

        flow['real_server_isn'] = syn_ack_packet[TCP].seq
        flow['seq_delta'] = flow['spoofed_server_isn'] - flow['real_server_isn']
        flow['state'] = 'ESTABLISHED'

        return flow

    def get_seq_delta(self, flow_key):
        """Get the sequence number delta for rewriting"""
        return self.flows[flow_key]['seq_delta']

# Global flow table instance
flow_table = FlowTable()
```

### 4. SYN-ACK from Server (Drop and Record)

When the real SYN-ACK arrives from the server (via ServerNIC), we drop it but record the sequence number:

```python
def handle_server_packet(packet):
    """Process packets from ServerNIC (originally from server)"""
    tcp_layer = packet[TCP]

    if is_syn_ack_packet(tcp_layer):
        # Record the real server ISN but DON'T forward to client
        flow_key = extract_flow_key(packet)
        flow_table.update_with_real_syn_ack(packet)

        log_event(f"Real SYN-ACK captured, delta calculated: {flow_table.get_seq_delta(flow_key)}")
        # Packet is dropped - client already has spoofed SYN-ACK

    else:
        # Regular data from server - rewrite ACK numbers
        handle_server_data(packet)
```

### 5. Sequence Number Rewriting

For packets from client to server, rewrite SEQ numbers:

```python
def handle_client_data(packet):
    """Handle data packets from client (ACK or PSH-ACK)"""
    flow_key = extract_flow_key(packet)

    # Wait until we have the delta (real SYN-ACK received)
    if not flow_table.has_delta(flow_key):
        buffer_packet(packet, flow_key)  # Queue until delta is known
        return

    # Rewrite sequence numbers
    seq_delta = flow_table.get_seq_delta(flow_key)
    rewritten_packet = rewrite_seq_numbers(packet, seq_delta)

    # Forward to ServerNIC
    forward_packet(rewritten_packet, interface='eth1')
    log_event(f"Client data rewritten and forwarded")
```

For packets from server to client, rewrite ACK numbers:

```python
def handle_server_data(packet):
    """Handle data packets from server"""
    flow_key = extract_flow_key(packet)
    seq_delta = flow_table.get_seq_delta(flow_key)

    # Rewrite acknowledgment numbers (inverse delta)
    rewritten_packet = rewrite_ack_numbers(packet, -seq_delta)

    # Forward to client
    forward_packet(rewritten_packet, interface='eth0')
    log_event(f"Server data rewritten and forwarded to client")
```

### 6. Packet Rewriting Implementation

```python
def rewrite_seq_numbers(packet, delta):
    """Rewrite TCP sequence numbers and recalculate checksums"""
    # Create a copy to avoid modifying original
    new_packet = packet.copy()

    # Adjust sequence number
    new_packet[TCP].seq = (packet[TCP].seq + delta) & 0xFFFFFFFF

    # Recalculate checksums
    recalculate_checksums(new_packet)

    return new_packet

def rewrite_ack_numbers(packet, delta):
    """Rewrite TCP acknowledgment numbers and recalculate checksums"""
    new_packet = packet.copy()

    # Adjust acknowledgment number
    new_packet[TCP].ack = (packet[TCP].ack + delta) & 0xFFFFFFFF

    # Recalculate checksums
    recalculate_checksums(new_packet)

    return new_packet

def recalculate_checksums(packet):
    """Recalculate IP and TCP checksums after modification"""
    # Delete existing checksums to force recalculation
    del packet[IP].chksum
    del packet[TCP].chksum

    # Scapy will auto-recalculate when packet is sent
    return packet
```

### 7. Main Entry Point

```python
def main():
    """Main entry point for ClientNIC"""
    print("Starting ClientNIC VM...")
    print("Interfaces: eth0 (client), eth1 (ServerNIC)")

    # Initialize logging
    setup_logging()

    # Start packet capture (blocking)
    start_packet_capture()

if __name__ == "__main__":
    main()
```

## Key Design Decisions

1. **Immediate SYN-ACK Response**: The spoofed SYN-ACK is sent immediately when a SYN is received, enabling 0-RTT data transmission.

2. **Flow State Tracking**: Each connection is tracked with its sequence number delta, allowing transparent rewriting of all subsequent packets.

3. **Buffering Strategy**: Packets from the client may arrive before the real SYN-ACK is received. These are buffered until the delta is calculated.

4. **Checksum Recalculation**: After modifying sequence/ack numbers, IP and TCP checksums must be recalculated to ensure packet validity.

## Module Structure

```
client_nic/
├── main.py              # Entry point, starts sniffers on eth0/eth1
├── handlers.py          # packet_handler logic for 0-RTT
├── flow_table.py        # Track connections, seq deltas
├── rewriter.py          # Modify seq/ack, recalc checksum
├── spoofer.py           # Craft spoofed SYN-ACK
└── logger.py            # Log packets for demo proof
```

## Testing Considerations

- Verify spoofed SYN-ACK has correct sequence numbers
- Ensure sequence number delta is calculated correctly
- Test checksum recalculation
- Verify packet buffering during handshake
- Test with multiple concurrent connections

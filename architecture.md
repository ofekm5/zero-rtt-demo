# NIC VM Code Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  main.py                                                    │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ sniffer     │───▶│ flow_table  │───▶│ forwarder   │     │
│  │             │    │             │    │             │     │
│  │ sniff()     │    │ track state │    │ sendp()     │     │
│  │ on eth0     │    │ seq deltas  │    │ on eth0/1   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                  │                  ▲             │
│         ▼                  ▼                  │             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ packet_handler(pkt)                                  │  │
│  │                                                      │  │
│  │   if SYN from client:                                │  │
│  │       spoof_syn_ack(pkt) → send to eth0 (client)     │  │
│  │       forward(pkt) → send to eth1 (server)           │  │
│  │       flow_table.create(pkt)                         │  │
│  │                                                      │  │
│  │   if SYN-ACK from server:                            │  │
│  │       drop (don't forward)                           │  │
│  │       flow_table.record_server_seq(pkt)              │  │
│  │                                                      │  │
│  │   if DATA from client:                               │  │
│  │       rewrite_seq(pkt, flow_table.get_delta())       │  │
│  │       forward(pkt) → eth1                            │  │
│  │                                                      │  │
│  │   if DATA from server:                               │  │
│  │       rewrite_ack(pkt, flow_table.get_delta())       │  │
│  │       forward(pkt) → eth0                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Modules

```
nic_vm/
├── main.py              # Entry point, starts sniffers
├── handlers.py          # packet_handler logic
├── flow_table.py        # Track connections, seq deltas
├── rewriter.py          # Modify seq/ack, recalc checksum
├── spoofer.py           # Craft spoofed SYN-ACK
└── logger.py            # Log packets for demo proof
```

## Key Data Structure

```python
# flow_table.py
class FlowTable:
    def __init__(self):
        self.flows = {}  # keyed by (client_ip, client_port, server_ip, server_port)
    
    def create(self, syn_pkt):
        key = self._key(syn_pkt)
        self.flows[key] = {
            "client_isn": syn_pkt[TCP].seq,
            "spoofed_server_isn": random_seq(),  # what we told client
            "real_server_isn": None,             # filled when server responds
            "delta": None                        # calculated after server SYN-ACK
        }
    
    def record_server_seq(self, syn_ack_pkt):
        key = self._key(syn_ack_pkt)
        flow = self.flows[key]
        flow["real_server_isn"] = syn_ack_pkt[TCP].seq
        flow["delta"] = flow["spoofed_server_isn"] - flow["real_server_isn"]
```
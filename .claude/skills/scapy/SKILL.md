---
name: scapy
description: Network packet manipulation with Scapy. Use when constructing, sniffing, modifying, or sending raw network packets. Covers layer-by-layer packet building, BPF filtering, kernel integration, and common pitfalls.
---

# Scapy Packet Manipulation

## Core Concepts

Scapy wraps `AF_PACKET` raw sockets for direct network access. It handles checksums, lengths, and protocol fields automatically.

## Packet Construction

ALWAYS use the `/` operator to stack layers:

```python
from scapy.all import Ether, IP, TCP, UDP, Raw

# TCP SYN packet
pkt = Ether()/IP(dst="10.0.0.1")/TCP(dport=80, flags="S")

# UDP with payload
pkt = Ether()/IP(dst="10.0.0.1")/UDP(dport=53)/Raw(load=b"data")
```

**Key patterns:**
- Layer order matters: `Ether/IP/TCP` (not reversed)
- Scapy auto-calculates: checksums, lengths, IDs
- To force recalculation after modification: `del pkt[TCP].chksum`

## Sending Packets

```python
sendp(pkt, iface="eth0")      # Layer 2 — YOU control Ethernet header
send(pkt)                      # Layer 3 — kernel adds Ethernet header
sr1(pkt)                       # Send and wait for ONE reply
srp(pkt, iface="eth0")        # Layer 2 send-receive
```

**MUST specify `iface`** when using `sendp()` or `srp()` — no default interface.

## Sniffing Packets

```python
# Callback-based (blocking)
sniff(iface="eth0", prn=handler, filter="tcp port 80")

# Capture to list
packets = sniff(iface="eth0", count=10, timeout=5)

# Async sniffing
t = AsyncSniffer(iface="eth0", prn=handler)
t.start()
# ... do work ...
t.stop()
```

**The `filter` parameter uses BPF syntax** (same as tcpdump). Filtering happens in kernel — more efficient than Python-side filtering.

## Packet Inspection & Modification

```python
def handler(pkt):
    # Check layer existence BEFORE accessing
    if TCP in pkt:
        seq = pkt[TCP].seq
        pkt[TCP].seq = seq + 1
        del pkt[TCP].chksum    # MUST delete to force recalc
        sendp(pkt, iface="eth0")

    # Access raw bytes
    raw_bytes = bytes(pkt)

    # Pretty print
    pkt.show()
```

**Common field access:**
- `pkt[IP].src`, `pkt[IP].dst` — IP addresses
- `pkt[TCP].sport`, `pkt[TCP].dport` — ports
- `pkt[TCP].flags` — "S", "SA", "A", "F", "R", etc.
- `pkt[TCP].seq`, `pkt[TCP].ack` — sequence numbers
- `pkt[Raw].load` — payload bytes

## Kernel Integration (Critical)

**AF_PACKET sockets receive COPIES, not the original packet:**

```
NETWORK CORE
    │
    ├──→ Copy to AF_PACKET socket (scapy sees it)
    │
    └──→ ip_rcv() → normal stack processing continues
```

**Implications:**
- The kernel STILL processes the original packet
- Kernel may send RST for unknown TCP connections
- Kernel may respond to pings, ARP requests, etc.

**To prevent kernel interference:**
```bash
# Drop outgoing RSTs
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# Drop specific traffic
iptables -A OUTPUT -p tcp --dport 80 -j DROP
```

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| Checksum invalid | Modified packet without clearing | `del pkt[TCP].chksum` |
| Kernel sends RST | Kernel doesn't know about your connection | Add iptables DROP rule |
| No packets received | Wrong interface or need root | Check `iface=`, run as root |
| Filter not working | Invalid BPF syntax | Test with `tcpdump -d "filter"` |
| sendp() fails | Missing interface | Add `iface="eth0"` |

## Quick Reference

```python
# Parse pcap
packets = rdpcap("capture.pcap")

# Write pcap
wrpcap("out.pcap", packets)

# Forge response to received packet
def respond(pkt):
    if TCP in pkt and pkt[TCP].flags == "S":
        resp = Ether(dst=pkt[Ether].src)/\
               IP(dst=pkt[IP].src)/\
               TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,
                   flags="SA", seq=1000, ack=pkt[TCP].seq+1)
        sendp(resp, iface="eth0")
```

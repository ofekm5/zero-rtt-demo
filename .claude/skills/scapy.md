# Scapy Reference

Use this skill when working with Scapy for packet manipulation in this project.

---

## High-Level Overview

Scapy is a Python library that wraps `AF_PACKET` sockets and provides:

### 1. Packet Construction

Build packets layer by layer with `/` operator:

```python
from scapy.all import Ether, IP, TCP

pkt = Ether()/IP(dst="10.0.0.1")/TCP(dport=80, flags="S")
```

Each layer is a class with fields you can set. Scapy auto-calculates checksums, lengths, etc. when you send.

### 2. Sniffing (Receiving)

```python
# Blocking loop — calls your function for each packet
sniff(iface="eth0", prn=my_handler, filter="tcp")

# Or capture to list
packets = sniff(iface="eth0", count=10)
```

The `filter` uses BPF syntax (same as tcpdump) for kernel-level filtering before packets reach Python.

### 3. Sending

```python
sendp(pkt, iface="eth0")      # Layer 2 (Ethernet frame)
send(pkt)                      # Layer 3 (IP, kernel handles Ethernet)
```

### 4. Packet Inspection/Modification

```python
def handler(pkt):
    if TCP in pkt:
        print(pkt[TCP].seq)       # Read fields
        pkt[TCP].seq = 12345      # Modify fields
        del pkt[TCP].chksum       # Force recalculation
        sendp(pkt, iface="eth1")  # Forward modified
```

---

## Kernel Integration

When you use scapy (which opens an `AF_PACKET` raw socket), the NETWORK CORE delivers a **copy** of the packet to your raw socket *and* continues normal processing through the protocol handler.

```
NETWORK CORE
    │
    ├──→ Copy to AF_PACKET socket (scapy sees it)
    │
    └──→ ip_rcv() → normal stack processing continues
```

The packet isn't stolen — it's duplicated. Both paths run in parallel. On "NIC" VMs you need to drop or block the original packet (via iptables) to prevent the kernel from responding with RSTs or interfering with spoofed responses.

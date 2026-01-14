# Scapy Kernel Integration

When you use scapy (which opens an `AF_PACKET` raw socket), the NETWORK CORE delivers a **copy** of the packet to your raw socket *and* continues normal processing through the protocol handler.

```
NETWORK CORE
    │
    ├──→ Copy to AF_PACKET socket (scapy sees it)
    │
    └──→ ip_rcv() → normal stack processing continues
```

So the packet isn't stolen — it's duplicated. Both paths run in parallel. That's why on your "NIC" VM you'd need to also drop or block the original packet (via iptables) to prevent the kernel from responding with RSTs or interfering with your spoofed responses.
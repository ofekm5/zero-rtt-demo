# Zero-RTT TCP Demonstration Overview

## Executive Summary

This project demonstrates a novel approach to reducing TCP connection latency by eliminating the traditional 3-way handshake delay. By implementing intelligent middleware that spoofs server responses, clients can send data immediately upon connection initiation, achieving "zero round-trip time" (0-RTT) for the first data transmission. While not suitable for production use.

## Problem Statement

### Current State
Standard TCP connections require a 3-way handshake (SYN, SYN-ACK, ACK) before any application data can be transmitted. This introduces a minimum of one full round-trip time (RTT) before data exchange begins, which can be significant in high-latency networks.

### Impact
- **Latency-sensitive applications** (e.g., API calls, microservices) suffer from connection setup overhead
- **Short-lived connections** spend a disproportionate amount of time in handshake rather than data transfer
- **User experience** degrades in high-latency environments (satellite, cellular, intercontinental links)

### Example Scenario
```
Traditional TCP (1-RTT minimum):
  t=0ms:   Client sends SYN
  t=50ms:  Server responds with SYN-ACK (50ms RTT)
  t=100ms: Client sends ACK + DATA
  → Data transmission begins at t=100ms

Zero-RTT TCP (this project):
  t=0ms:   Client sends SYN, receives immediate spoofed SYN-ACK, sends DATA
  → Data transmission begins at t=0ms (100ms saved)
```

## Solution Overview

This project implements a proof-of-concept 0-RTT TCP system using a **man-in-the-middle architecture** with two intelligent network components:

1. **ClientNIC VM**: Intercepts SYN packets, sends immediate spoofed SYN-ACK, manages sequence number translation
2. **ServerNIC VM**: Provides network isolation and transparent packet forwarding


## Related Documentation

- **[ClientNIC Technical Design](./architecture/clientNIC.md)** - Detailed implementation guide for the core 0-RTT component
- **[ServerNIC Technical Design](./architecture/serverNIC.md)** - Implementation guide for the forwarding component
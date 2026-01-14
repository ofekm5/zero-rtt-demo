# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## MANDATORY BEHAVIORAL REQUIREMENTS

### CRITICAL: Workflow Guidelines - NO EXCEPTIONS

**YOU MUST follow these rules before EVERY response without deviation:**

1. **Plan incrementally** - ALWAYS break complex tasks into small, trackable steps. NO monolithic approaches.
2. **Ask for clarification** - NEVER assume or guess missing requirements. STOP and ask if anything is unclear.
3. **Read selectively** - ONLY read explicitly needed files. NO broad directory scans or exploratory reading.
4. **Summarize concisely** - MAXIMUM 2-3 key findings and next steps. NO verbose explanations.

**VIOLATION OF THESE RULES IS UNACCEPTABLE.** If you find yourself about to violate these guidelines, STOP immediately and reconsider your approach.

### ABSOLUTE Response Style Requirements

**Default format for non-code answers (STRICTLY ENFORCED):**
- HARD LIMIT: 2-3 paragraphs maximum
- NEVER repeat previously established context
- ONLY provide actionable information
- NO unnecessary elaboration or preambles

**Code changes (MANDATORY):**
- Show ACTUAL file changes with diffs - descriptions are insufficient
- Explain rationale briefly (1-2 sentences max)
- Test ALL changes before claiming task completion
- NO untested code submissions

### NON-NEGOTIABLE Restrictions

**These restrictions override ANY other considerations, including helpfulness:**

- **NEVER create README files** unless user explicitly requests "create a README"
- **NEVER create documentation files** without explicit user request
- **ALWAYS prefer editing existing files** over creating new ones
- **PR titles/descriptions MUST be clear and concise** - no flowery language

**If you're tempted to violate these restrictions "because it would be helpful," STOP. These are non-negotiable requirements, not suggestions.**

### Enforcement Notice

These guidelines are **MANDATORY REQUIREMENTS**, not optional best practices. Any justification like "not always relevant" or "it would be more helpful to..." is a violation. When in conflict between these rules and your default behaviors, **THESE RULES WIN**.

## Project Overview

This is a proof-of-concept demonstrating **0-RTT TCP** - a technique to eliminate the traditional 3-way handshake latency by using intelligent middleware that spoofs server responses. This allows clients to send application data immediately without waiting for the full handshake to complete, saving approximately 50-200ms (1-RTT) per connection.

**IMPORTANT**: This is an educational/demonstration project only. Not suitable for production use.

## Architecture

The system consists of 4 VMs connected in series:

```
Client VM → ClientNIC VM → ServerNIC VM → Server VM
```

### Component Responsibilities

1. **Client VM** (`client-app/`): Standard unmodified TCP client application
2. **ClientNIC VM** (`clientnic/`): **Core 0-RTT logic** - intercepts SYN packets, sends spoofed SYN-ACK, manages sequence number translation
3. **ServerNIC VM** (`servernic/`): Simple transparent packet forwarder between ClientNIC and Server
4. **Server VM** (`server-app/`): Standard unmodified TCP server application

### Key Technical Concepts

#### Sequence Number Translation
The ClientNIC maintains a **flow table** tracking each connection's sequence number delta:
- When SYN arrives from client → immediately send spoofed SYN-ACK with random ISN (spoofed_server_isn)
- Forward original SYN to server → receive real SYN-ACK → record real ISN (real_server_isn)
- Calculate delta: `seq_delta = spoofed_server_isn - real_server_isn`
- All client→server packets: rewrite SEQ by adding delta
- All server→client packets: rewrite ACK by subtracting delta

#### Flow Processing Pipeline

**ClientNIC handles packets in two directions:**

From Client (eth0):
1. SYN → send spoofed SYN-ACK + forward to ServerNIC
2. ACK/DATA → buffer until delta known, then rewrite SEQ and forward

From ServerNIC (eth1):
1. Real SYN-ACK → drop (already sent spoofed one), record real ISN, calculate delta
2. DATA → rewrite ACK and forward to client

**ServerNIC is stateless:**
- eth1 (from ClientNIC) → forward to eth2 (to Server)
- eth2 (from Server) → forward to eth1 (to ClientNIC)

#### Packet Modification
After rewriting sequence/acknowledgment numbers, **checksums must be recalculated**:
```python
del packet[IP].chksum
del packet[TCP].chksum
# Scapy auto-recalculates on send
```

## Technology Stack

- **Python 3.8+**: All components written in Python
- **Scapy**: Packet manipulation library (wraps AF_PACKET raw sockets)
- **Linux**: Required for raw socket support and virtual networking
- **Network setup**: VMs connected via virtual networks (bridge/veth)

### Scapy Essentials

Scapy provides:
- **Packet construction**: Layer-by-layer with `/` operator: `IP(dst="10.0.0.1")/TCP(flags="S")`
- **Sniffing**: `sniff(iface="eth0", prn=handler, filter="tcp")`
- **Sending**: `sendp(packet, iface="eth0")` (Layer 2) or `send(packet)` (Layer 3)
- **Modification**: Access fields like `packet[TCP].seq`, delete checksums to force recalc

## Key Documentation

- **`docs/architecture.md`**: Complete system architecture, requirements, protocol flow
- **`clientnic/docs/clientNIC.md`**: Detailed ClientNIC implementation (0-RTT core logic)
- **`servernic/docs/serverNIC.md`**: ServerNIC forwarding implementation
- **`docs/scapy/scapy-guide.md`**: Scapy usage reference
- **`docs/overview.md`**: Problem statement and solution overview

## Development Workflow

Since this is currently a **documentation-only repository** (no code implementation yet), development will follow:

1. Implement basic client/server TCP applications (standard Python sockets)
2. Implement ServerNIC stateless forwarding (Scapy sniff + sendp)
3. Implement ClientNIC 0-RTT logic:
   - Flow table management
   - SYN interception and spoofed SYN-ACK generation
   - Sequence number rewriting
   - Packet buffering during handshake
4. Set up VM networking (4 VMs with virtual networks)
5. Test end-to-end connectivity and measure latency reduction

## Testing Approach

### Unit Testing
- Flow table operations (create, update, lookup)
- Sequence number rewriting algorithms
- Checksum recalculation correctness

### Integration Testing
- End-to-end connection establishment
- Data transmission correctness
- Multiple concurrent connections
- Connection teardown (FIN/RST)

### Performance Testing
- Measure time-to-first-byte with/without 0-RTT
- Expected improvement: 1-RTT reduction (50-200ms depending on network latency)
- Test with simulated high-latency networks

## Important Constraints

### Protocol Limitations
- **TCP only** (not UDP, QUIC, etc.)
- Does not handle TCP options (timestamps, window scaling, SACK)
- Assumes reliable network (no packet reordering)

### Security Warnings
- **Educational/demo use only** - not production-ready
- No encryption or authentication
- Vulnerable to packet injection in real networks
- Should only be used in isolated/controlled environments

### Implementation Notes
- Flow identification uses 4-tuple: (src_ip, src_port, dst_ip, dst_port)
- All sequence number arithmetic must use 32-bit wraparound: `& 0xFFFFFFFF`
- Client and server applications remain **completely unmodified** - transparency is key
- Packet buffering required: client may send data before real SYN-ACK arrives

## Module Structure (Planned)

```
client-app/
├── client.py           # Standard TCP client

clientnic/
├── main.py             # Entry point, sniffers on eth0/eth1
├── handlers.py         # SYN interception, 0-RTT logic
├── flow_table.py       # Connection state and seq delta tracking
├── rewriter.py         # Seq/ack modification, checksum recalc
└── spoofer.py          # Spoofed SYN-ACK generation

servernic/
├── main.py             # Simple packet forwarder
└── logger.py           # Optional packet logging

server-app/
└── server.py           # Standard TCP server
```

# High-Level Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Client VM     │         │  ClientNIC VM   │         │  ServerNIC VM   │         │   Server VM     │
│                 │         │  (0-RTT logic)  │         │  (forwarding)   │         │                 │
│  Python app     │───eth0──│  Scapy/raw      │───eth1──│  Scapy/raw      │───eth2──│  Simple TCP     │
│  sends data     │         │  sockets        │         │  sockets        │         │  server         │
└─────────────────┘         └─────────────────┘         └─────────────────┘         └─────────────────┘
       │                            │                            │                            │
       │ ① SYN                      │                            │                            │
       │───────────────────────────>│                            │                            │
       │                            │ ② SYN (forwarded)          │                            │
       │                            │───────────────────────────>│ ③ SYN (forwarded)          │
       │                            │                            │───────────────────────────>│
       │ ④ Spoofed SYN-ACK          │                            │                            │
       │<───────────────────────────│                            │ ⑤ Real SYN-ACK (captured)  │
       │                            │                            │<───────────────────────────│
       │ ⑥ ACK + DATA (early)       │                            │         (dropped)          │
       │───────────────────────────>│                            │                            │
       │                            │ ⑦ ACK + DATA (seq rewrite) │                            │
       │                            │───────────────────────────>│ ⑧ ACK + DATA (forwarded)   │
       │                            │                            │───────────────────────────>│
       │                            │                            │ ⑨ Server response          │
       │                            │ ⑩ Response (ack rewrite)   │<───────────────────────────│
       │ ⑪ Response to client       │<───────────────────────────│                            │
       │<───────────────────────────│                            │                            │
```

## Key Components

### 1. Client VM
**Purpose**: Standard TCP client application (unmodified)

**Characteristics**:
- Uses standard TCP sockets
- No awareness of 0-RTT optimization
- Sends data immediately after receiving SYN-ACK

### 2. ClientNIC VM (Core Innovation)
**Purpose**: Intelligent middleware implementing 0-RTT optimization

**Key Responsibilities**:
- Intercept client SYN packets
- Generate and send spoofed SYN-ACK with fabricated sequence number
- Track connection state and sequence number deltas
- Rewrite sequence/acknowledgment numbers in all subsequent packets
- Drop real SYN-ACK from server (after recording sequence number)

**[→ Detailed Technical Design](./architecture/clientNIC.md)**

### 3. ServerNIC VM
**Purpose**: Network isolation and transparent forwarding

**Key Responsibilities**:
- Forward packets between ClientNIC and Server without modification
- Provide network separation for clean architecture
- Optional packet logging for demonstration purposes

**[→ Detailed Technical Design](./architecture/serverNIC.md)**

### 4. Server VM
**Purpose**: Standard TCP server application (unmodified)

**Characteristics**:
- Uses standard TCP sockets
- No awareness of 0-RTT optimization
- Processes packets as if from normal TCP client

## Core Functional Requirements

### FR-1: Immediate SYN-ACK Response
**Requirement**: Upon receiving a SYN packet from the client, ClientNIC must immediately generate and send a spoofed SYN-ACK response.

**Success Criteria**:
- Response sent within <1ms of SYN receipt
- Valid TCP SYN-ACK packet structure
- Randomly generated Initial Sequence Number (ISN)

### FR-2: Transparent Sequence Number Translation
**Requirement**: All packets must have sequence/acknowledgment numbers rewritten to maintain protocol correctness.

**Success Criteria**:
- Client-to-server packets: SEQ rewritten based on delta
- Server-to-client packets: ACK rewritten based on delta
- Connection proceeds without TCP errors or retransmissions

### FR-3: Flow State Management
**Requirement**: Track all active connections with their sequence number deltas.

**Success Criteria**:
- Unique identification of flows by 4-tuple (src_ip, src_port, dst_ip, dst_port)
- Correct calculation of sequence number delta
- Support for multiple concurrent connections

### FR-4: Real SYN-ACK Handling
**Requirement**: Capture and drop the real SYN-ACK from the server while recording its sequence number.

**Success Criteria**:
- Real SYN-ACK never reaches the client
- Server ISN correctly recorded in flow table
- Sequence delta correctly calculated

### FR-5: Checksum Recalculation
**Requirement**: Recalculate IP and TCP checksums after packet modification.

**Success Criteria**:
- All modified packets have valid checksums
- No checksum-related packet drops
- Server accepts all forwarded packets

## Non-Functional Requirements

### NFR-1: Latency Reduction
**Requirement**: Demonstrate measurable reduction in time-to-first-byte for client data transmission.

**Target**: 1-RTT reduction (approximately 50-200ms depending on network latency)

### NFR-2: Transparency
**Requirement**: Client and server applications require no modifications.

**Criteria**: Standard TCP socket code works without changes

### NFR-3: Correctness
**Requirement**: All data must be transmitted correctly without corruption.

**Criteria**:
- No TCP retransmissions due to sequence number errors
- Application-layer data integrity maintained
- Connection teardown (FIN) handled correctly

### NFR-4: Observability
**Requirement**: System must provide logging/tracing for demonstration and debugging.

**Criteria**:
- Packet-level logging available
- Flow state visible for debugging
- Clear demonstration of 0-RTT benefit

## System Constraints

### Technical Constraints
- Requires layer-2 packet manipulation (raw sockets/Scapy)
- Operates at network layer (not application layer)
- Requires dedicated VMs or network namespaces for isolation

### Security Constraints
- **Educational/demo use only** - not suitable for production
- No encryption or authentication
- Vulnerable to packet injection attacks
- Should only be used in controlled network environments

### Protocol Constraints
- TCP only (not UDP, QUIC, etc.)
- Does not handle TCP options (timestamps, window scaling, SACK)
- Assumes reliable network (no packet reordering)

## Success Metrics

1. **Latency Reduction**: Client can send data 1-RTT (50-200ms) earlier than standard TCP
2. **Correctness**: 100% of test connections complete successfully without errors
3. **Transparency**: Zero modifications required to client/server applications
4. **Concurrency**: Support ≥10 simultaneous connections without performance degradation

## Out of Scope

The following are explicitly **not** included in this demonstration:

- Production-ready implementation
- Security hardening or encryption
- Connection migration or failover
- Performance optimization for high-throughput scenarios
- Support for protocols other than TCP
- Integration with existing network infrastructure

## Technical Stack
- **Python 3.8+**
- **Scapy**: Packet manipulation and crafting
- **Linux**: Raw socket support, virtual networking (bridge, veth)
- **Virtualization**: VMs or network namespaces for component isolation
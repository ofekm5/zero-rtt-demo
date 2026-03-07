# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Important VM Setup info
All the 4 VMs in this setup are part of AWS CDK stack, called smartnics_stack. The CDK code lives in `infra/` in this repo (mirrored from `C:\Users\shir\Documents\GitHub\private-core-cdk-stack`, excluding the gitlab runner stack).

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

### Architecture & Design
- **`.claude/context/architecture.md`**: Complete system architecture, requirements, protocol flow
- **`clientnic/docs/clientNIC.md`**: Detailed ClientNIC implementation (0-RTT core logic)
- **`servernic/docs/serverNIC.md`**: ServerNIC forwarding implementation

### Reference
- **`.claude/skills/scapy/SKILL.md`**: Scapy usage reference (packet construction, sniffing, sending)
- **`.claude/skills/zero-rtt-integration-tester/SKILL.md`**: Integration tester skill (run tests, diagnose failures)
- **`.claude/skills/zero-rtt-integration-tester/references/troubleshooting.md`**: Known issues and debugging tips
- **`.claude/skills/zero-rtt-integration-tester/references/test-scripts.md`**: run_all.sh and analyze_capture.py reference

### Integration Testing
- **`integration-test/scripts/run_all.sh`**: Full automated end-to-end test orchestrator (runs locally, drives all 4 VMs via SSM)
- **`integration-test/scripts/analyze_capture.py`**: pcap analysis — validates spoofed SYN-ACK, ISN delta, timing, checksums
- **`integration-test/reports/`**: Test run reports

Startup order: **Server → ServerNIC → ClientNIC → Client**

### Agent System Prompts
Specialist agent prompts under `.claude/context/agents-system-prompts/`:
- **`clientnic-developer.md`**: ClientNIC 0-RTT logic developer agent
- **`servernic-developer.md`**: ServerNIC forwarder developer agent
- **`integration-tester.md`**: Integration testing agent

## Development Status

- [x] ServerNIC stateless forwarder (`servernic/main.py`)
- [x] Client TCP application (`client-app/client.py`)
- [x] Server TCP application (`server-app/server.py`)
- [x] ClientNIC 0-RTT logic (`clientnic/`)
- [x] Integration test suite (`integration-test/scripts/`)

## Development Workflow

All components are implemented. Current focus is integration testing and bug fixes:

1. Run `./integration-test/scripts/run_all.sh` to execute the full test suite
2. Investigate failures using the manual steps in `.claude/skills/zero-rtt-integration-tester/SKILL.md`
3. File findings in `integration-test/reports/`

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

## Module Structure

```
client-app/
├── client.py           # Standard TCP client
└── test_client.py      # Client unit tests

clientnic/
├── main.py             # Entry point, sniffers on eth0/eth1
├── handlers.py         # SYN interception, 0-RTT logic
├── flow_table.py       # Connection state and seq delta tracking
├── rewriter.py         # Seq/ack modification, checksum recalc
├── spoofer.py          # Spoofed SYN-ACK generation
├── logger.py           # Packet logging
├── test_flow_table.py  # Flow table unit tests
├── test_handlers.py    # Handler unit tests
├── test_spoofer.py     # Spoofer unit tests
├── README.md
└── docs/
    └── clientNIC.md    # Detailed ClientNIC design doc

servernic/
├── main.py             # Simple packet forwarder
├── forwarder.py        # Forwarding logic
├── logger.py           # Packet logging
├── test_forwarder.py   # Forwarder unit tests
└── docs/
    └── serverNIC.md    # Detailed ServerNIC design doc

server-app/
├── server.py           # Standard TCP server
└── test_server.py      # Server unit tests

integration-test/
├── scripts/
│   ├── run_all.sh          # Full end-to-end test orchestrator (local → 4 VMs via SSM)
│   └── analyze_capture.py  # pcap analysis: spoofed SYN-ACK, ISN delta, timing, checksums
└── reports/                # Test run reports (e.g. integration-test-report-YYYY-MM-DD.md)

infra/                  # AWS CDK infrastructure (deploy the 4-VM topology)
├── app.py              # CDK entry point
├── cdk.json            # CDK app config
├── cdk.context.json    # Cached AZ lookups (eu-central-1)
├── requirements.txt    # CDK Python dependencies
├── deploy.ps1          # Deploy script (uses repo-root venv/)
├── destroy.ps1         # Destroy script (uses repo-root venv/)
├── ARCHITECTURE.md     # Infra architecture notes
└── cdk/
    ├── packet_test_stack.py   # VPC with Client/Middle/Server subnets
    └── smartnics_stack.py     # EC2 instances, ENIs, route tables

venv/                   # Shared Python venv for local dev (all components)
```

### Deploying Infrastructure

```powershell
cd infra
.\deploy.ps1          # Creates/activates repo-root venv, installs deps, deploys
.\deploy.ps1 -Bootstrap  # First-time CDK bootstrap + deploy
.\destroy.ps1         # Tear down all stacks
```

Retrieve the SSH private key after deploy:
```bash
aws ssm get-parameter --name <KeyPairParameterName> --with-decryption \
  --query Parameter.Value --output text > smartnics-key.pem
chmod 400 smartnics-key.pem
```

# zero-rtt-demo

Proof-of-concept demonstrating **0-RTT TCP** — eliminating the 3-way handshake latency by using intelligent middleware (ClientNIC) that spoofs server SYN-ACKs, allowing clients to send application data immediately without waiting for the real handshake to complete (~50-200ms saved per connection).

**Educational/demo use only. Not suitable for production.**

## Architecture

```
Client VM → ClientNIC VM → ServerNIC VM → Server VM
10.1.0.x     10.1.0.x        10.1.1.x      10.1.2.x
             (eth0/eth1)     (eth0/eth1)
```

| Component | Role |
|-----------|------|
| `client-app/` | Standard unmodified TCP client |
| `clientnic/` | Core 0-RTT logic — intercepts SYN, sends spoofed SYN-ACK, rewrites sequence numbers |
| `servernic/` | Stateless transparent packet forwarder |
| `server-app/` | Standard unmodified TCP server |
| `infra/` | AWS CDK stack that provisions the 4-VM topology |

## Packet Flow

```
Client VM          ClientNIC VM        ServerNIC VM        Server VM
    │                    │                    │                    │
    │ ① SYN              │                    │                    │
    │───────────────────>│                    │                    │
    │                    │ ② SYN (forwarded)  │                    │
    │                    │───────────────────>│ ③ SYN (forwarded)  │
    │                    │                    │───────────────────>│
    │ ④ Spoofed SYN-ACK  │                    │                    │
    │<───────────────────│                    │ ⑤ Real SYN-ACK     │
    │                    │                    │<───────────────────│
    │ ⑥ ACK + DATA (early│                    │    (dropped)       │
    │───────────────────>│                    │                    │
    │                    │ ⑦ ACK+DATA         │                    │
    │                    │  (seq rewritten)   │                    │
    │                    │───────────────────>│ ⑧ ACK+DATA         │
    │                    │                    │───────────────────>│
    │                    │                    │ ⑨ Server response  │
    │                    │ ⑩ Response         │<───────────────────│
    │                    │  (ack rewritten)   │                    │
    │ ⑪ Response         │<───────────────────│                    │
    │<───────────────────│                    │                    │
```

**Key**: ClientNIC sends the spoofed SYN-ACK (④) before the real one (⑤) even arrives, so the client can send data (⑥) a full RTT earlier than normal TCP. The real SYN-ACK is dropped; sequence numbers are transparently rewritten (⑦, ⑩) so the server never knows.

## Sequence Number Translation

ClientNIC maintains a flow table with a per-connection `seq_delta`:

```
delta = spoofed_server_isn - real_server_isn   (mod 2^32)

client→server packets:  TCP.seq += delta
server→client packets:  TCP.ack -= delta
```

After rewriting, Scapy recalculates checksums automatically (`del pkt[IP].chksum; del pkt[TCP].chksum`).

## Infrastructure

The AWS CDK stack in `infra/` provisions the full environment in `eu-central-1`:

- **VPC** `10.1.0.0/16` with 3 public subnets: `Client` (`10.1.0.0/24`), `Middle` (`10.1.1.0/24`), `Server` (`10.1.2.0/24`)
- **4 EC2 instances** (t3.micro, Amazon Linux 2) with source/dest check disabled on NIC VMs
- **Custom route tables** that enforce the chain topology at the network level
- **SSM access** for all instances (no bastion or SSH key needed)
- **ip_forward=1** set persistently via sysctl.conf on NIC VMs at boot

```powershell
cd infra
.\deploy.ps1            # Creates venv, installs CDK deps, deploys
.\deploy.ps1 -Bootstrap # First-time CDK bootstrap + deploy
.\destroy.ps1           # Tear down all stacks
```

## Running the Tests

```bash
./integration-test/scripts/run_all.sh
```

Discovers all 4 VMs via AWS SSM, pulls latest code, starts services in the correct order, runs 3 client connections, captures packets, and validates 0-RTT behavior. Exit code = number of failures.

See `.claude/skills/zero-rtt-integration-tester/SKILL.md` for manual diagnostic steps.

## Quick Start (manual, on the VMs)

Startup order: **Server → ServerNIC → ClientNIC → Client**

```bash
# 1. Server VM
cd /home/ec2-user/zero-rtt-demo
setsid python3 server-app/server.py --host 0.0.0.0 --port 8080 --verbose < /dev/null >> /tmp/server.log 2>&1 &

# 2. ServerNIC VM
cd /home/ec2-user/zero-rtt-demo
setsid python3 -m servernic.main < /dev/null >> /tmp/servernic.log 2>&1 &

# 3. ClientNIC VM
cd /home/ec2-user/zero-rtt-demo
setsid python3 -m clientnic.main < /dev/null >> /tmp/clientnic.log 2>&1 &

# 4. Client VM
cd /home/ec2-user/zero-rtt-demo
python3 client-app/client.py --host <server-ip> --port 8080 --mode repeated --count 3 --verbose
```

> All VMs: connect via `aws ssm start-session --target <instance-id> --region eu-central-1`

## Success Criteria

| Check | Expected |
|-------|----------|
| Connections | 3/3 succeed |
| Spoofed SYN-ACK | Arrives at client before real SYN-ACK |
| ISN delta | Non-zero, consistent across all packets |
| Checksums | Zero bad checksums on eth0 and eth1 |
| Flow table | delta logged for every connection |

## Constraints

- TCP only (no UDP, QUIC)
- Does not handle TCP options (timestamps, window scaling, SACK)
- No encryption or authentication — isolated/controlled environments only
- Assumes reliable network (no packet reordering)

## Technology Stack

- Python 3.8+, Scapy (AF_PACKET raw sockets), Linux
- AWS CDK v2 (Python) for infrastructure

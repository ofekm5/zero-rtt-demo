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

## Infrastructure

The AWS CDK stack in `infra/` provisions the full environment in `eu-central-1`:

- **VPC** `10.1.0.0/16` with 3 public subnets: `Client` (`10.1.0.0/24`), `Middle` (`10.1.1.0/24`), `Server` (`10.1.2.0/24`)
- **4 EC2 instances** (t3.micro, Amazon Linux 2) with source/dest check disabled on NIC VMs
- **Custom route tables** that enforce the chain topology at the network level
- **SSM access** for all instances (no bastion needed)

```bash
cd infra
pip install -r requirements.txt
cdk deploy --all
```

After deploy, retrieve the SSH key:
```bash
aws ssm get-parameter --name <KeyPairParameterName> --with-decryption --query Parameter.Value --output text > smartnics-key.pem
chmod 400 smartnics-key.pem
```

## Quick Start

Startup order: **Server → ServerNIC → ClientNIC → Client**

```bash
# Server VM
cd /home/ec2-user/zero-rtt-demo && python3 server-app/server.py

# ServerNIC VM
cd /home/ec2-user/zero-rtt-demo && sudo python3 servernic/main.py

# ClientNIC VM
cd /home/ec2-user/zero-rtt-demo && sudo python3 clientnic/main.py

# Client VM
cd /home/ec2-user/zero-rtt-demo && python3 client-app/client.py
```

## Technology Stack

- Python 3.8+, Scapy (raw packet manipulation), Linux raw sockets
- AWS CDK v2 (Python) for infrastructure
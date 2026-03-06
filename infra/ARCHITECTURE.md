# Infrastructure Architecture

## CDK Stacks

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PacketTestStack                                                        │
│  (VPC + Subnets + Internet Gateway)                                     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ vpc (passed as prop)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  SmartNicsStack                                                         │
│  (EC2 Instances + ENIs + Security Groups + Route Tables + Key Pair)     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## VPC Layout  —  `PacketTestStack`

```
VPC: 10.1.0.0/16   (eu-central-1, single AZ)
│
├── Internet Gateway
│
├── Subnet: Client   10.1.0.0/24  (PUBLIC)
├── Subnet: Middle   10.1.1.0/24  (PUBLIC)
└── Subnet: Server   10.1.2.0/24  (PUBLIC)
```

---

## EC2 Instances & Network Interfaces  —  `SmartNicsStack`

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ VPC  10.1.0.0/16                                                                 │
│                                                                                  │
│  ┌─────────────────────────────┐                                                 │
│  │ Subnet: Client  10.1.0.0/24 │                                                 │
│  │                             │                                                 │
│  │  ┌──────────────────────┐   │                                                 │
│  │  │ smartnics-client     │   │                                                 │
│  │  │ t3.micro / AL2       │   │                                                 │
│  │  │ eth0: 10.1.0.x       │   │                                                 │
│  │  │ source/dest: OFF     │   │                                                 │
│  │  └──────────────────────┘   │                                                 │
│  │                             │                                                 │
│  │  ┌──────────────────────┐   │                                                 │
│  │  │ smartnics-clientnic  │   │                                                 │
│  │  │ t3.micro / AL2       │   │                                                 │
│  │  │ eth0: 10.1.0.x  ◄────┼───┼── primary ENI (Client subnet)                  │
│  │  │ source/dest: OFF     │   │                                                 │
│  │  └──────────┬───────────┘   │                                                 │
│  └─────────────┼───────────────┘                                                 │
│                │ eth1 (secondary ENI)                                            │
│  ┌─────────────┼───────────────────────────┐                                     │
│  │ Subnet: Middle  10.1.1.0/24             │                                     │
│  │             │                           │                                     │
│  │  ┌──────────▼───────────────────────┐   │                                     │
│  │  │ clientnic-middle-eni             │   │                                     │
│  │  │ eth1: 10.1.1.x  source/dest: OFF │   │                                     │
│  │  └──────────────────────────────────┘   │                                     │
│  │                                         │                                     │
│  │  ┌──────────────────────┐               │                                     │
│  │  │ smartnics-servernic  │               │                                     │
│  │  │ t3.micro / AL2       │               │                                     │
│  │  │ eth0: 10.1.1.x  ◄────┼───────────────┼── primary ENI (Middle subnet)       │
│  │  │ source/dest: OFF     │               │                                     │
│  │  └──────────┬───────────┘               │                                     │
│  └─────────────┼─────────────────────────────                                    │
│                │ eth1 (secondary ENI)                                            │
│  ┌─────────────┼───────────────┐                                                 │
│  │ Subnet: Server  10.1.2.0/24 │                                                 │
│  │             │               │                                                 │
│  │  ┌──────────▼───────────────────────┐   │                                     │
│  │  │ servernic-server-eni             │   │                                     │
│  │  │ eth1: 10.1.2.x  source/dest: OFF │   │                                     │
│  │  └──────────────────────────────────┘   │                                     │
│  │                                         │                                     │
│  │  ┌──────────────────────┐               │                                     │
│  │  │ smartnics-server     │               │                                     │
│  │  │ t3.micro / AL2       │               │                                     │
│  │  │ eth0: 10.1.2.x       │               │                                     │
│  │  └──────────────────────┘               │                                     │
│  └─────────────────────────────────────────┘                                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Routing Tables

### Client Subnet (10.1.0.0/24)
| Destination   | Target                              | Purpose                        |
|---------------|-------------------------------------|--------------------------------|
| 0.0.0.0/0     | Internet Gateway                    | SSH / internet access          |
| 10.1.2.0/24   | smartnics-clientnic (instance-id)   | Force traffic through ClientNIC|

### Middle Subnet (10.1.1.0/24)
| Destination   | Target                              | Purpose                        |
|---------------|-------------------------------------|--------------------------------|
| 0.0.0.0/0     | Internet Gateway                    | Boot-time git clone / pip      |
| 10.1.2.0/24   | smartnics-servernic (instance-id)   | Forward path → Server          |
| 10.1.0.0/24   | clientnic-middle-eni (ENI-id)       | Return path → Client           |

### Server Subnet (10.1.2.0/24)
| Destination   | Target                              | Purpose                        |
|---------------|-------------------------------------|--------------------------------|
| 0.0.0.0/0     | Internet Gateway                    | SSH / internet access          |
| 10.1.0.0/24   | servernic-server-eni (ENI-id)       | Return traffic → ClientNIC     |

---

## Security Groups

All four VMs share the same inbound rules pattern:

| Port / Protocol | Source          | Purpose              |
|-----------------|-----------------|----------------------|
| TCP 22          | 0.0.0.0/0       | SSH access           |
| All traffic     | 10.1.0.0/16     | Intra-VPC traffic    |

Outbound: all traffic allowed.

---

## IAM & Key Pair

| Resource              | Details                                              |
|-----------------------|------------------------------------------------------|
| EC2 Instance Role     | `AmazonSSMManagedInstanceCore` (SSM Session Manager) |
| Key Pair              | `smartnics-key` — private key stored in SSM Parameter Store |

---

## Packet Flow (0-RTT Chain)

```
Internet
   │  SSH (port 22)
   ▼
┌──────────────┐        ┌──────────────────┐        ┌──────────────────┐        ┌──────────────┐
│    Client    │        │   ClientNIC      │        │   ServerNIC      │        │    Server    │
│ 10.1.0.x     │──eth0──▶ eth0: 10.1.0.x  │──eth1──▶ eth0: 10.1.1.x  │──eth1──▶ 10.1.2.x    │
│              │        │ eth1: 10.1.1.x   │        │ eth1: 10.1.2.x   │        │              │
└──────────────┘        └──────────────────┘        └──────────────────┘        └──────────────┘
                         ▲ spoofed SYN-ACK            stateless forwarder
                         │ seq# translation
                         │ 0-RTT core logic
```

---

## CloudFormation Outputs  (`SmartNicsStack`)

| Output Key               | Description                              |
|--------------------------|------------------------------------------|
| `ClientInstanceId`       | EC2 instance ID of Client VM             |
| `ClientPublicIp`         | Public IP of Client VM                   |
| `ClientNicInstanceId`    | EC2 instance ID of ClientNIC VM          |
| `ClientNicPublicIp`      | Public IP of ClientNIC VM                |
| `ServerNicInstanceId`    | EC2 instance ID of ServerNIC VM          |
| `ServerNicPublicIp`      | Public IP of ServerNIC VM                |
| `ServerInstanceId`       | EC2 instance ID of Server VM             |
| `ServerPublicIp`         | Public IP of Server VM                   |
| `KeyPairParameterName`   | SSM parameter path for the SSH private key |

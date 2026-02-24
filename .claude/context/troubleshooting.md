# Troubleshooting Reference

Consolidated lessons from integration testing sessions (Jan–Feb 2026).

---

## AWS Infrastructure

### Security Groups

Default-deny. Every traffic type must be explicitly allowed.

Required rules for the 4-VM setup:
```bash
# Allow application port within VPC
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol tcp --port 8080 --cidr 10.1.0.0/16

# Allow ICMP for ping/debug
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol icmp --port -1 --cidr 10.1.0.0/16

# Allow all traffic within the security group (self-referencing)
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol -1 --source-group <sg-id>
```

**Permanent fix**: Add these rules to `private-core-cdk-stack/cdk/smartnics_stack.py`.

### VPC Routing

All VMs are in the same VPC (10.1.0.0/16) across separate subnets. AWS routes traffic directly between subnets by default, bypassing the NIC instances. You must override route tables to force traffic through the NIC VMs.

| Subnet | Route Table Change |
|--------|--------------------|
| Client (10.1.0.0/24) | Route 10.1.2.0/24 → ClientNIC eth0 ENI |
| Middle (10.1.1.0/24) | Route 10.1.2.0/24 → ServerNIC eth1 ENI |
| Server (10.1.2.0/24) | Route 10.1.0.0/24 → ServerNIC eth1 ENI |

Also needed on ClientNIC VM itself (instance-level route):
```bash
sudo ip route add 10.1.2.0/24 via 10.1.1.36 dev eth1
```

**Note**: VM IPs change on instance restart. Always query fresh IPs before testing.

### IP Forwarding

Must be enabled on NIC VMs:
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# Verify
cat /proc/sys/net/ipv4/ip_forward  # must be 1
```

Also disable source/dest check on EC2 instances in the AWS console or via CLI.

---

## SSM Daemon Detachment

### Problem

Running background processes via SSM `send-command` hangs indefinitely:
```bash
# BROKEN - SSM tracks child processes, never reaches "Success"
nohup sudo python3 server.py ... &
```

SSM agent waits for all child processes to complete. `nohup ... &` still leaves the process as an SSM child.

### Solution

Use `setsid` with full file descriptor redirection:
```bash
# CORRECT
setsid python3 server.py --host 0.0.0.0 --port 8080 < /dev/null > /tmp/server.log 2>&1 &
```

Or double-fork:
```bash
(nohup python3 server.py > /tmp/server.log 2>&1 &) &
```

Key elements:
- `setsid` — creates new session, detaches from controlling terminal
- `< /dev/null` — detaches stdin
- `> /tmp/log 2>&1` — redirects stdout/stderr so SSM doesn't wait on them
- `&` — backgrounds the process

**Verification after start**:
```bash
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ss -tlnp | grep 8080"]' \
  --targets "Key=instanceIds,Values=<instance-id>"
```

**Polling**: After 2–3 polls showing "InProgress" with no progress, switch approach rather than continue waiting.

---

## Scapy: sendp() vs send()

### The Bug (Fixed in commit 5d4f6cd)

`clientnic/rewriter.py` used `sendp()` to forward packets between subnets. This caused packets to appear on the outgoing interface but never arrive at the destination.

**Root cause**: `sendp()` sends at Layer 2 (Ethernet), preserving original MAC addresses. When forwarding a packet received on eth0 out through eth1:
- Source MAC remains: Client's MAC
- Dest MAC remains: ClientNIC's eth0 MAC

Both are wrong for the eth1→ServerNIC hop. The packet is sent but silently dropped.

**tcpdump evidence**:
```
08:36:08 02:01:63:ea:d8:bf > 02:a5:ee:1e:cd:ed, 10.1.0.177.44064 > 10.1.2.206.8080: [S]
#                              ^ ClientNIC's own eth1 MAC as dest -- wrong
```

### Fix

```python
# BEFORE (broken)
sendp(packet, iface=iface, verbose=False)

# AFTER (correct)
from scapy.sendrecv import send
send(packet[IP], iface=iface, verbose=False)
```

`send()` operates at Layer 3: it strips the Ethernet frame, lets the kernel routing table resolve the next hop, and ARP resolves the correct destination MAC.

| | `sendp()` | `send()` |
|-|-----------|----------|
| Layer | 2 (Ethernet) | 3 (IP) |
| MAC handling | Preserves existing | Kernel ARP resolution |
| Routing | None | Kernel routing table |
| Use case | Same-subnet, controlled MACs | Cross-subnet, routed traffic |

**Rule of thumb**: When forwarding between subnets (NIC VMs), always use `send()`.

---

## Packet Capture Diagnostics

Always capture on both sides of a hop to isolate where packets are lost:

```bash
# ClientNIC - client side (eth0)
sudo tcpdump -i eth0 -nn -tttt 'tcp port 8080' -w /tmp/client_side.pcap

# ClientNIC - server side (eth1)
sudo tcpdump -i eth1 -nn -tttt 'tcp port 8080' -w /tmp/server_side.pcap

# Quick live view
sudo tcpdump -i any -nn 'tcp port 8080' -c 20
```

Verify checksums (should return empty):
```bash
tshark -r /tmp/capture.pcap -Y "tcp.checksum_bad==1"
```

---

## Integration Test Baseline Results (2026-01-28)

After all fixes applied, 5/5 connections successful:
- Kernel forwarding TTFB: ~2.6 ms
- ClientNIC 0-RTT TTFB: ~1.7 ms
- 0-RTT sequence confirmed: spoofed SYN-ACK sent before real SYN-ACK arrives

**Still to test**: sequence number translation under load, concurrent connections, FIN/RST teardown.

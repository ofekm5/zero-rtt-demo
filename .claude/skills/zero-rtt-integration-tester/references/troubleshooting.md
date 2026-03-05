# Troubleshooting Reference

Consolidated lessons from integration testing sessions (Jan-Feb 2026).

## Contents
- [SSM Daemon Detachment](#ssm-daemon-detachment)
- [Scapy sendp() vs send()](#scapy-sendp-vs-send)
- [Spoofed SYN-ACK Arrives Late](#spoofed-syn-ack-arrives-late)
- [ServerNIC Interface Names](#servernic-interface-names)
- [SSM git pull Fails](#ssm-git-pull-fails)
- [AWS Security Groups](#aws-security-groups)
- [VPC Routing](#vpc-routing)
- [Baseline Results](#baseline-results)

---

## SSM Daemon Detachment

**Problem**: `nohup sudo python3 server.py ... &` via SSM hangs indefinitely. SSM agent waits for all child processes; `nohup ... &` still leaves the process as an SSM child.

**Fix** — use `setsid` with full fd redirection:
```bash
setsid python3 server.py --host 0.0.0.0 --port 8080 < /dev/null > /tmp/server.log 2>&1 &
```
Or double-fork:
```bash
(nohup python3 server.py > /tmp/server.log 2>&1 &) &
```
Key elements: `setsid` creates new session, `< /dev/null` detaches stdin, `> /tmp/log 2>&1` redirects stdout/stderr.

After 2-3 polls showing "InProgress" with no progress, switch approach rather than continue waiting.

---

## Scapy sendp() vs send()

**Bug** (fixed in commit 5d4f6cd): `clientnic/rewriter.py` used `sendp()` to forward packets between subnets. Packets appeared on the outgoing interface but never arrived at destination.

**Root cause**: `sendp()` sends at Layer 2, preserving original MAC addresses. When forwarding eth0->eth1, source and dest MACs are wrong for the next hop — packet is silently dropped.

**tcpdump evidence**:
```
08:36:08 02:01:63:ea:d8:bf > 02:a5:ee:1e:cd:ed, 10.1.0.177.44064 > 10.1.2.206.8080: [S]
#                              ^ ClientNIC's own eth1 MAC as dest -- wrong
```

**Fix**:
```python
# BEFORE (broken)
sendp(packet, iface=iface, verbose=False)

# AFTER (correct)
from scapy.sendrecv import send
send(packet[IP], iface=iface, verbose=False)
```

`send()` operates at Layer 3: strips Ethernet, lets kernel routing + ARP resolve correct MACs.

**Rule**: When forwarding between subnets (NIC VMs), always use `send()`.

---

## Spoofed SYN-ACK Arrives Late

**Problem** (2026-02-26): Capture analysis reports spoofed SYN-ACK not seen on eth0, even though ClientNIC logs show `send()` was called.

**Root cause**: Scapy's `sniff()` uses a single callback thread. Filter `"tcp"` intercepts heavy AWS instance metadata traffic to `169.254.169.254:80`. Each metadata SYN generates two `send()` calls, backing up the queue. Intra-VPC RTT is ~500us — by the time the test SYN callback fires, the real SYN-ACK has already been forwarded by the kernel, completing the handshake. The spoofed SYN-ACK arrives late and is RST'd.

**Fix** — narrow the sniff filter in `clientnic/main.py`:
```python
sniff(
    iface="eth0",
    prn=client_handler.handle,
    filter="tcp and not host 169.254.169.254 and dst port 8080",
    store=False,
)
```

---

## ServerNIC Interface Names

**Problem**: `servernic.main` defaulted to `--client-iface eth1 --server-iface eth2`, but the VM only has eth0 and eth1:
```
eth0: 10.1.1.x/24  <- middle subnet, faces ClientNIC
eth1: 10.1.2.x/24  <- server subnet, faces Server
```
Caused: `ValueError: Interface 'eth2' not found`

**Fix**: Updated defaults in `servernic/main.py` to `eth0`/`eth1`. No CLI flags needed for standard deployment.

---

## SSM git pull Fails

**Problem**: `git config --global ...` via SSM fails — SSM executes as root without `$HOME`:
```
fatal: $HOME not set
```

**Fix**:
```bash
sudo -u ec2-user git -C /home/ec2-user/zero-rtt-demo pull origin main
```

---

## AWS Security Groups

Default-deny. Required rules for the 4-VM setup:
```bash
# Application port within VPC
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol tcp --port 8080 --cidr 10.1.0.0/16

# ICMP for ping/debug
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol icmp --port -1 --cidr 10.1.0.0/16

# All traffic within same security group
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol -1 --source-group <sg-id>
```

**Permanent fix**: Add these rules to `infra/cdk/smartnics_stack.py`.

---

## VPC Routing

AWS routes traffic directly between subnets by default, bypassing NIC instances. Route tables must be overridden:

| Subnet | Route | Target |
|--------|-------|--------|
| Client (10.1.0.0/24) | 10.1.2.0/24 | ClientNIC eth0 ENI |
| Middle (10.1.1.0/24) | 10.1.2.0/24 | ServerNIC eth0 ENI |
| Middle (10.1.1.0/24) | 10.1.0.0/24 | ClientNIC eth1 ENI |
| Server (10.1.2.0/24) | 10.1.0.0/24 | ServerNIC eth1 ENI |

Also add instance-level route on ClientNIC VM:
```bash
sudo ip route add 10.1.2.0/24 via <servernic-eth0-ip> dev eth1
```

**Note**: VM IPs change on restart. Query fresh IPs before testing.

---

## Baseline Results

After all fixes applied (2026-01-28), 5/5 connections successful:
- Kernel forwarding TTFB: ~2.6 ms
- ClientNIC 0-RTT TTFB: ~1.7 ms
- Spoofed SYN-ACK confirmed sent before real SYN-ACK arrives

**Still to test**: sequence number translation under load, concurrent connections, FIN/RST teardown.

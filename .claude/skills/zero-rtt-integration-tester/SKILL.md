---
name: zero-rtt-integration-tester
description: End-to-end integration testing for the 0-RTT TCP demo across all 4 VMs (Client, ClientNIC, ServerNIC, Server). Use when running integration tests, validating 0-RTT behavior, diagnosing packet flow issues, verifying sequence number translation, or troubleshooting the 4-VM chain topology on AWS. Triggers on phrases like "run integration tests", "test 0-RTT", "check the VMs", "verify packet flow", "debug the demo", or "validate the setup".
---

# 0-RTT Integration Tester

## How to run integration tests

### Step 1 — Run the automated script

```bash
./integration-test/scripts/run_all.sh
```

Exit code = number of failures. The script handles VM discovery, git pull, service startup, packet capture, client test, log checks, and pcap analysis automatically.

See `references/test-scripts.md` for the full step-by-step breakdown and expected output of both scripts (`run_all.sh` and `analyze_capture.py`).

### Step 2 — Investigate any failures

The script reports pass/fail but cannot diagnose *why* something failed. When any check fails:

1. **Read the logs** — the script prints them inline; look for the first anomaly
2. **SSM into the relevant VM** and run the manual diagnostic commands below
3. **Cross-correlate**: clientnic log + pcap + server log together tell the full story
4. **Report observed vs expected** for each failed check with exact log lines or packet timestamps

Common failure patterns and their fixes are in `references/troubleshooting.md`.

---

## Manual / Interactive Testing

Use the steps below when the script fails partway, or to run individual checks in isolation.

## VM Access

Discover instance IDs and IPs:
```bash
aws ec2 describe-instances --filters "Name=tag:Name,Values=smartnics-*" \
  --query "Reservations[].Instances[].[Tags[?Key=='Name'].Value|[0],InstanceId,PublicIpAddress,PrivateIpAddress]" \
  --output table --region eu-central-1
```

Connect via SSM (no SSH key needed):
```bash
aws ssm start-session --target <instance-id> --region eu-central-1
```

**Note**: VM IPs change on instance restart. Always query fresh IPs before testing.

## Startup Order

Always start in this order: **Server -> ServerNIC -> ClientNIC -> Client**

```bash
# 1. Server VM
cd /home/ec2-user/zero-rtt-demo && echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> /tmp/server.log && setsid python3 server-app/server.py --host 0.0.0.0 --port 8080 < /dev/null >> /tmp/server.log 2>&1 &

# 2. ServerNIC VM
cd /home/ec2-user/zero-rtt-demo && echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> /tmp/servernic.log && setsid python3 -m servernic.main < /dev/null >> /tmp/servernic.log 2>&1 &

# 3. ClientNIC VM
cd /home/ec2-user/zero-rtt-demo && echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> /tmp/clientnic.log && setsid python3 -m clientnic.main < /dev/null >> /tmp/clientnic.log 2>&1 &

# 4. Client VM
cd /home/ec2-user/zero-rtt-demo && python3 client-app/client.py
```

Verify server is listening before proceeding:
```bash
ss -tlnp | grep 8080
```

## Pre-flight Checks

Run on NIC VMs before starting:
```bash
# IP forwarding must be 1
cat /proc/sys/net/ipv4/ip_forward

# Check interface names (may not be eth0/eth1 on all AMIs)
ip link show

# Enable IP forwarding if needed (CDK sets this persistently; only needed if CDK wasn't run)
echo 1 > /proc/sys/net/ipv4/ip_forward
```

## Verification Checklist

### 1. Basic Connectivity
- Client sends data, server receives it correctly
- Check server log: `tail -f /tmp/server.log`

### 2. 0-RTT Behavior
Spoofed SYN-ACK must arrive at client **before** the real SYN-ACK:
```bash
# Capture on ClientNIC eth0 (client-facing)
tcpdump -i eth0 -nn -tttt 'tcp port 8080' -w /tmp/client_side.pcap

# Capture on ClientNIC eth1 (server-facing)
tcpdump -i eth1 -nn -tttt 'tcp port 8080' -w /tmp/server_side.pcap
```
Compare SYN-ACK timestamps: spoofed (eth0) must precede real (eth1 inbound -> eth0 forwarded).

### 3. Sequence Number Translation
- Spoofed ISN must differ from real ISN
- Delta must be applied correctly on all subsequent packets
- Check ClientNIC logs: `tail -f /tmp/clientnic.log` for "delta calculated" entries

### 4. Checksum Integrity
Must return empty (no bad checksums):
```bash
tshark -r /tmp/capture.pcap -Y "tcp.checksum_bad==1"
```

### 5. Flow Table State
Logs must show delta calculated per connection:
```bash
grep -E "delta|flow|SYN" /tmp/clientnic.log
```

## Packet Capture Diagnostics

Always capture on both sides of each hop to isolate where packets are lost:
```bash
# Live view (quick check)
tcpdump -i any -nn 'tcp port 8080' -c 20
```

## Updating Code on VMs

Run git pull as ec2-user (SSM runs as root without $HOME):
```bash
sudo -u ec2-user git -C /home/ec2-user/zero-rtt-demo pull origin main
```

## Known Issues

See `references/troubleshooting.md` for documented bugs and fixes:
- SSM daemon detachment (use `setsid`, not `nohup ... &`)
- Scapy `sendp()` vs `send()` for cross-subnet forwarding
- Spoofed SYN-ACK arriving late (sniff filter too broad — excludes `169.254.169.254`)
- ServerNIC interface name mismatch
- Security group rules needed for port 8080 and ICMP

## Reporting

For each check, report **observed vs expected** explicitly. Flag any deviation. Never modify application code — only observe and report.

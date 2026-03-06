---
name: zero-rtt-integration-tester
description: End-to-end integration testing for the 0-RTT TCP demo across all 4 VMs (Client, ClientNIC, ServerNIC, Server). Use when running integration tests, validating 0-RTT behavior, diagnosing packet flow issues, verifying sequence number translation, or troubleshooting the 4-VM chain topology on AWS. Triggers on phrases like "run integration tests", "test 0-RTT", "check the VMs", "verify packet flow", "debug the demo", or "validate the setup".
---

# 0-RTT Integration Tester

## Automated Test Run (preferred)

Run the full suite locally — it discovers VMs, pulls latest code, starts all services, and validates 0-RTT behavior automatically:

```bash
./tests/integration/run_all.sh
```

Exit code = number of failures. See `references/test-scripts.md` for the full step-by-step breakdown and expected output of both scripts (`run_all.sh` and `analyze_capture.py`).

---

## Manual / Interactive Testing

Use the steps below for debugging or running individual checks.

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
cd /home/ec2-user/zero-rtt-demo && setsid python3 server-app/server.py --host 0.0.0.0 --port 8080 < /dev/null > /tmp/server.log 2>&1 &

# 2. ServerNIC VM
cd /home/ec2-user/zero-rtt-demo && setsid sudo python3 -m servernic.main < /dev/null > /tmp/servernic.log 2>&1 &

# 3. ClientNIC VM
cd /home/ec2-user/zero-rtt-demo && setsid sudo python3 -m clientnic.main < /dev/null > /tmp/clientnic.log 2>&1 &

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

# Enable IP forwarding if needed
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Verification Checklist

### 1. Basic Connectivity
- Client sends data, server receives it correctly
- Check server log: `tail -f /tmp/server.log`

### 2. 0-RTT Behavior
Spoofed SYN-ACK must arrive at client **before** the real SYN-ACK:
```bash
# Capture on ClientNIC eth0 (client-facing)
sudo tcpdump -i eth0 -nn -tttt 'tcp port 8080' -w /tmp/client_side.pcap

# Capture on ClientNIC eth1 (server-facing)
sudo tcpdump -i eth1 -nn -tttt 'tcp port 8080' -w /tmp/server_side.pcap
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
sudo tcpdump -i any -nn 'tcp port 8080' -c 20
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

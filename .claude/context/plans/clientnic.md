# ClientNIC VM — Integration Test Runbook

Run this entirely on the **ClientNIC VM**. Every cross-VM dependency is preceded by a `[WAIT]` block.

---

## Step 0: Export Instance ID

Run from your **local machine** before connecting.

```bash
export CLIENTNIC_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-clientnic" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

echo "ClientNIC: $CLIENTNIC_ID"
```

---

> **[WAIT]** Confirm ServerNIC is running (`servernic.main`) and the Server VM is listening on port 8080 before continuing.
>
> **Press Enter to continue.**

---

## Step 1: Connect via SSM

```bash
aws ssm start-session --target $CLIENTNIC_ID
```

---

## Step 2: Start Packet Captures (Before Client Connects)

Start these **before** running the client so the full handshake is captured.

**Terminal A — eth0 (client-facing side):**
```bash
sudo tcpdump -i eth0 -nn -tttt 'tcp port 8080' -w /tmp/client_side.pcap
```

**Terminal B (second SSM session) — eth1 (server-facing side):**
```bash
sudo tcpdump -i eth1 -nn -tttt 'tcp port 8080' -w /tmp/server_side.pcap
```

Leave both running.

---

## Step 3: Start ClientNIC

In a **third SSM session** to the ClientNIC VM:

```bash
cd /home/ec2-user/zero-rtt-demo
sudo python3 -m clientnic.main
```

ClientNIC will print startup info and wait for packets.

---

> **[WAIT]** Switch to the Client VM runbook and run the client request.
> Come back here once the client has completed (printed a response or errored).
>
> **Press Enter to analyze captures.**

---

## Step 4: Stop Captures and Analyze

Stop `tcpdump` in terminals A and B with `Ctrl+C`.

### 4a. View eth0 capture (client side)

```bash
tcpdump -nn -tttt -r /tmp/client_side.pcap
```

**Expected sequence on eth0:**
1. `SYN` from client
2. `SYN-ACK` to client ← **SPOOFED**, timestamp is earlier than the real one
3. `ACK` from client
4. `DATA` from client

The spoofed SYN-ACK must appear **before** the real SYN-ACK (which arrives later on eth1).

### 4b. Verify spoofed SYN-ACK appears before real SYN-ACK

```bash
# Spoofed SYN-ACK timestamp (on eth0, direction: server→client)
tcpdump -nn -tttt -r /tmp/client_side.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0'

# Real SYN-ACK timestamp (on eth1, direction: server→clientnic)
tcpdump -nn -tttt -r /tmp/server_side.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0'
```

The timestamp on eth0 must be **earlier** than on eth1.

---

## Step 5: Verify Sequence Number Translation

```bash
# SYN on eth0 — client's ISN (spoofed server ISN will be in the SYN-ACK)
tcpdump -nn -r /tmp/client_side.pcap 'tcp[tcpflags] & tcp-syn != 0'

# SYN on eth1 — forwarded SYN to server (real server ISN in the real SYN-ACK)
tcpdump -nn -r /tmp/server_side.pcap 'tcp[tcpflags] & tcp-syn != 0'
```

The SYN-ACK SEQ on eth0 (spoofed) should differ from the SYN-ACK SEQ on eth1 (real).

```
delta = spoofed_server_isn - real_server_isn
```

Subsequent client→server packets should have their SEQ shifted by `+delta`, and server→client packets should have ACK shifted by `-delta`.

---

## Step 6: Verify Checksums

```bash
tshark -r /tmp/client_side.pcap -Y "tcp.checksum_bad==1"
```

Expected: **no output** (no bad checksums).

---

## Step 7: Check Flow Table Delta Log

```bash
cat /tmp/clientnic.log | grep "delta"
```

Expected: at least one log line recording a calculated delta for the test flow.

---

## Troubleshooting

### No packets captured on eth0 or eth1

```bash
# Confirm interface names
ip link show

# Test with no filter first
sudo tcpdump -i eth0 -nn tcp -c 10
```

If interface names differ from `eth0`/`eth1` (e.g., `ens5`, `enp0s3`), update the `tcpdump` commands and `clientnic/main.py` accordingly.

### ClientNIC not intercepting SYN

```bash
# Confirm clientnic.main is running
ps aux | grep clientnic

# Check that tcpdump captures SYN arriving on eth0
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0'
```

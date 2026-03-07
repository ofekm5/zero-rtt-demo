# Integration Test Report — 2026-03-06

## Environment

| VM | Instance ID | Private IP |
|----|-------------|------------|
| smartnics-server | i-08abbb86deee7eb4b | 10.1.2.83 |
| smartnics-servernic | i-0571907b390d80bfe | 10.1.1.60 (eth0), 10.1.2.53 (eth1) |
| smartnics-clientnic | i-000bf0ef59cfef498 | 10.1.0.89 (eth0), 10.1.1.70 (eth1) |
| smartnics-client | i-039417a7c9e37f500 | 10.1.0.183 |

All 4 VMs were `running` at test start. Code was up to date (`git pull` = Already up to date on all VMs).

---

## Check 1 — Basic Connectivity ✅ PASS

Client ran 3 connections to server at `10.1.2.83:8080`:

```
=== Repeated Connection Test (3 connections) ===
  Connection 1: 3.62 ms
  Connection 2: 2.38 ms
  Connection 3: 1.98 ms

Results:
  Success: 3/3 (100%)
  TTFB Statistics:
    Min:     1.98 ms
    Max:     3.62 ms
    Average: 2.66 ms
    Median:  2.38 ms
    Std Dev: 0.85 ms
```

---

## Check 2 — Infrastructure Pre-flight ✅ PASS

| Check | ClientNIC | ServerNIC |
|-------|-----------|-----------|
| `ip_forward` | 1 ✓ | 1 ✓ |
| Interfaces | eth0, eth1 ✓ | eth0, eth1 ✓ |
| Route added | `10.1.2.0/24 via 10.1.1.60 dev eth1` ✓ | `10.1.0.0/24 via 10.1.1.70 dev eth0` ✓ |

Server confirmed listening: `ss -tlnp` showed `python3` on `:8080` (pid 5813).

---

## Check 3 — ServerNIC Forwarding ✅ PASS

- Process running: `python3 -m servernic.main` (pid 6307)
- Log confirmed: `Starting ServerNIC... Forwarding between eth0 (ClientNIC) <-> eth1 (Server)`
- Active bidirectional packet forwarding observed in logs

**Note:** `WARNING: MAC address to reach destination not found. Using broadcast` — expected behaviour for Scapy L3 `send()` in VPC (AWS resolves ARP transparently).

---

## Check 4 — 0-RTT Flow Table State ✅ PASS

ClientNIC log confirmed for all 3 port-8080 connections:

| Step | Observed |
|------|----------|
| `SYN received, flow created` | ✓ (flows: dport 35642, 35656, 35662) |
| `Spoofed SYN-ACK sent to client` | ✓ (3×) |
| `Original SYN forwarded to server` | ✓ (3×) |
| `Real SYN-ACK received, delta=<N>` | ✓ all non-zero |

Deltas observed:
- Flow 35642: `delta=2147109702`
- Flow 35656: `delta=2036050490`
- Flow 35662: `delta=2638251276`

---

## Check 5 — Packet Captures ✅ CAPTURED (analysis incomplete)

| File | Size |
|------|------|
| `/tmp/client_side.pcap` (eth0, client-facing) | 186 KB |
| `/tmp/server_side.pcap` (eth1, server-facing) | 24 KB |

Detailed SYN-ACK timing comparison and checksum validation were not completed (test interrupted before analysis step).

---

## Deviations / Issues Found

### ⚠️ Issue 1 — Packets Dropped Instead of Buffered (Medium)

```
WARNING: Data from server for unknown/unready flow: FlowKey(src_ip='10.1.2.83', src_port=8080, dst_ip='10.1.0.183', dst_port=35642)
```

Server data arrives at ClientNIC before the Real SYN-ACK is processed and the delta is calculated. Packets are **dropped** rather than buffered. The CLAUDE.md spec requires buffering:

> "Packet buffering required: client may send data before real SYN-ACK arrives"

Connections still succeed because the client retransmits, but this breaks strict 0-RTT semantics and adds latency. The `clientnic/` implementation does not implement the buffer-and-replay mechanism.

---

### ⚠️ Issue 2 — Multiple Real SYN-ACKs per Flow (Medium)

Flow 35642 logged 4 Real SYN-ACKs with different deltas:
```
delta=2147109702
delta=2036050490
delta=2014109123
delta=2638251276
```

This suggests RST/retry loops, or the flow table is being overwritten on duplicate SYN-ACKs. The delta being applied to subsequent packets may be inconsistent.

---

### ℹ️ Info 3 — Server Log Overwritten

`/tmp/server.log` only contained the error from a second (failed) start attempt that overwrote the file. The server itself was confirmed running via `ss -tlnp`. For future runs: append logs or use a unique filename per run.

---

### ℹ️ Info 4 — `analyze_capture.py` Not Deployed to VMs

`tests/integration/analyze_capture.py` does not exist on the VMs (directory `tests/` missing). The automated pcap analysis described in `references/test-scripts.md` could not run. Manual analysis was attempted but interrupted.

---

### ℹ️ Info 5 — SSM + `sudo` Hangs

`setsid sudo python3 ...` via SSM hangs indefinitely. Workaround: drop `sudo` — SSM `AWS-RunShellScript` already runs as root on Linux.

---

## Not Verified

- Spoofed SYN-ACK timestamp vs real SYN-ACK timestamp (0-RTT timing check)
- Checksum integrity (`tshark -Y 'tcp.checksum_bad==1'`)
- Sequence number rewriting correctness on data packets

---

## Overall Result

| Check | Result |
|-------|--------|
| Basic connectivity (3/3) | ✅ PASS |
| Infrastructure pre-flight | ✅ PASS |
| ServerNIC forwarding | ✅ PASS |
| Flow table state (delta, spoof, forward) | ✅ PASS |
| Packet buffering | ❌ FAIL — packets dropped, not buffered |
| Multiple SYN-ACKs per flow | ⚠️ INVESTIGATE |
| 0-RTT timing (eth0 vs eth1 timestamps) | ⬜ NOT TESTED |
| Checksum integrity | ⬜ NOT TESTED |

# Integration Test Report — 2026-03-07

## Environment

| VM | Instance ID | Private IP |
|----|-------------|------------|
| smartnics-server | i-0395314c5ce4c454e | 10.1.2.70 |
| smartnics-servernic | i-0f49b16f4558d3e3d | 10.1.1.86 (eth0), 10.1.2.205 (eth1) |
| smartnics-clientnic | i-014a9000e218941cf | 10.1.0.23 (eth0), 10.1.1.99 (eth1) |
| smartnics-client | i-0e5bd741ab1eac1d2 | 10.1.0.25 |

Region: eu-central-1. All 4 VMs running. Code pulled from `main` before each run.

---

## Test Runs

Three consecutive runs were performed as bugs were discovered and fixed.

### Run 1 — 4 failures

**Bugs found:**

1. **ClientNIC sniffing AWS metadata traffic** — sniff filter `"tcp"` matched `169.254.169.254:80` requests, creating bogus flows, triggering broadcast MAC warnings, and delaying real SYN processing.
2. **SYN retransmits overwriting flow entries** — each retransmitted SYN called `create_flow()` unconditionally, replacing the existing entry (and its `spoofed_isn`) with a new one, destroying any delta already calculated.
3. **`analyze_capture.py` path wrong** — `run_all.sh` referenced `tests/integration/analyze_capture.py` but the file is at `integration-test/scripts/analyze_capture.py`.
4. **Server `ss` check timing** — starting the server daemon and checking `ss` in a single SSM command caused SSM to hang waiting for the background process.

**Fixes (commit `c1127d2`):**
- Sniff filter changed to `"tcp and not host 169.254.169.254"` on both eth0 and eth1
- Added `get_flow()` guard in `_handle_syn()` to skip SYN retransmits
- Fixed `analyze_capture.py` path in `run_all.sh`

### Run 2 — 4 failures

**Bug found:**

5. **Scapy `send(iface=...)` ignored** — `send()` is L3 and ignores the `iface` parameter (Scapy prints `SyntaxWarning: 'iface' has no effect on L3 I/O send()`). All forwarded packets went out via the default route (eth0) instead of eth1. Evidence: `server_side.pcap` was 24 bytes (header only, zero packets).

**Fix (commit `5334f72`):**
- Added OS routes on NIC VMs: `ip route replace 10.1.2.0/24 via 10.1.1.1 dev eth1` (ClientNIC), `ip route replace 10.1.0.0/24 via 10.1.1.1 dev eth0` (ServerNIC)
- Split server start and listen check into separate SSM calls

### Run 3 — ALL CHECKS PASSED

Full `run_all.sh` output:

```
[PASS] Server listening on :8080
[PASS] ServerNIC: IP forwarding enabled
[PASS] ClientNIC: IP forwarding enabled (set persistently by CDK)
[PASS] All 3 client connections succeeded
[PASS] tcpdump stopped
[PASS] Server received data from client
[PASS] ClientNIC: flow table entries seen in log
[PASS] Packet capture analysis: all checks passed
```

---

## Run 3 — Detailed Results

### Check 1 — Basic Connectivity: PASS

```
=== Repeated Connection Test (3 connections) ===
Server: 10.1.2.70:8080

  Connection 1: 3.85 ms
  Connection 2: 2.42 ms
  Connection 3: 2.09 ms

Results:
  Success: 3/3 (100%)
  TTFB Statistics:
    Min:     2.09 ms
    Max:     3.85 ms
    Average: 2.79 ms
    Median:  2.42 ms
    Std Dev: 0.93 ms
```

### Check 2 — Server Received Data: PASS

```
[10.1.0.25:35460] Received 22 bytes
[10.1.0.25:35460] Sent 40 bytes
[10.1.0.25:35466] Received 22 bytes
[10.1.0.25:35466] Sent 40 bytes
[10.1.0.25:35476] Received 22 bytes
[10.1.0.25:35476] Sent 40 bytes
```

### Check 3 — ClientNIC Flow Table: PASS

3 flows created with non-zero deltas:
- Flow 35460: `delta=2256684151`
- Flow 35466: `delta=3316339486`
- Flow 35476: `delta=1982237799`

Buffered packet flush confirmed for flow 35466: `Flushed 6 buffered packets`.

### Check 4 — Packet Capture Analysis: PASS

| Sub-check | Result | Details |
|-----------|--------|---------|
| Real SYN-ACKs on eth1 | PASS | 5 SYN-ACKs captured |
| Spoofed SYN-ACKs on eth0 | PASS | 3 spoofed (distinct ISN), 5 forwarded-real |
| ISN deltas non-zero | PASS | 3 matched flows |
| Checksums eth0 | PASS | 72/72 valid |
| Checksums eth1 | PASS | 74/74 valid |

### Check 5 — 0-RTT Timing: FAIL (informational)

Spoofed SYN-ACK arrived **after** real SYN-ACK in all 3 flows:

| Flow | Spoofed late by |
|------|----------------|
| dport=35460 | 58 ms |
| dport=35466 | 300 ms |
| dport=35476 | 373 ms |

**Root cause:** Kernel `ip_forward=1` forwarded the SYN to the server and the real SYN-ACK back to the client at kernel speed (~microseconds). The client completed the TCP handshake using the real SYN-ACK before Scapy (userspace Python) could even process the original SYN. The spoofed SYN-ACK arrived too late to be used.

**Impact:** Connections succeeded via **kernel forwarding**, not via 0-RTT sequence number translation. The ClientNIC intercepted and translated packets, but the client had already established the connection with the real server ISN — making the translation unnecessary (and the translated packets likely caused RSTs or were ignored).

---

## Critical Finding: Kernel Forwarding Bypasses 0-RTT

With `ip_forward=1`, the kernel forwards TCP packets at line rate, racing Scapy's userspace processing. In intra-VPC conditions (sub-ms RTT), the kernel always wins. The 0-RTT mechanism is never actually exercised.

### Fix Applied (commit `9d018e9`, pending test)

1. **iptables FORWARD DROP for port 8080** on both NIC VMs — prevents kernel from forwarding application traffic; only Scapy handles it:
   ```bash
   iptables -A FORWARD -p tcp --dport 8080 -j DROP
   iptables -A FORWARD -p tcp --sport 8080 -j DROP
   ```

2. **Narrowed sniff filter to `tcp port 8080`** on both ClientNIC and ServerNIC — eliminates all non-application noise (metadata, HTTPS, etc.)

3. **iptables cleanup** added to the cleanup step in `run_all.sh` to prevent rule accumulation.

**Status:** Committed and pushed. Pending re-test on 2026-03-08.

---

## Commits This Session

| Commit | Description |
|--------|-------------|
| `c1127d2` | Fix metadata interception, SYN retransmit handling, analyze_capture.py path |
| `5334f72` | Add OS routes for NIC VMs, fix server startup check |
| `9d018e9` | Block kernel forwarding for port 8080, narrow sniff to tcp port 8080 |

---

## Overall Result

| Check | Result |
|-------|--------|
| Basic connectivity (3/3) | PASS |
| Server received data | PASS |
| Infrastructure pre-flight | PASS |
| Flow table state (delta, spoof, forward) | PASS |
| Spoofed SYN-ACK detection | PASS |
| ISN deltas non-zero | PASS |
| Checksum integrity (eth0 + eth1) | PASS |
| 0-RTT timing (spoofed before real) | FAIL (kernel forwarding race) |
| True 0-RTT packet translation | PENDING (iptables fix committed, awaiting re-test) |

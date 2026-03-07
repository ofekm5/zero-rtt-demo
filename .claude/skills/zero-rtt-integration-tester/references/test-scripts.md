# Integration Test Scripts

Located in `integration-test/scripts/` in the repo root.

---

## run_all.sh

Full end-to-end orchestrator. Runs locally, drives all 4 VMs via AWS SSM.

**Prerequisites**: `aws` CLI configured with SSM access, `python3` in PATH, `eu-central-1` region.

```bash
./integration-test/scripts/run_all.sh
```

Exit code = number of failed checks (0 = all passed).

### What it does (in order)

| Step | Action | Pass condition |
|------|--------|----------------|
| 0 | Discover EC2 instances by tag (`smartnics-*`) | All 4 IDs resolved |
| - | `git pull origin main` on all 4 VMs via SSM | (best-effort) |
| - | Kill leftover processes + delete old logs/pcaps | (cleanup) |
| 1 | Start Server (`setsid python3 server.py`) | `ss -tlnp` shows `:8080` |
| 2 | Enable IP forwarding, add route on ServerNIC, start servernic.main | `ip_forward == 1` |
| 3 | Enable IP forwarding, add route on ClientNIC, start tcpdump on eth0+eth1, start clientnic.main | `ip_forward == 1` |
| 4 | Run client (`--mode repeated --count 3 --verbose`) | `Success: 3/3` or `100%` in output |
| 5 | Stop tcpdump | (always passes) |
| 6 | Read `/tmp/server.log` | Contains `Received` or `bytes` |
| 7 | Read `/tmp/clientnic.log` | Contains `delta`, `flow created`, `SYN received`, or `spoofed` |
| 8 | Run `analyze_capture.py` on ClientNIC | `All checks passed` in output |

### Key implementation details

- Uses `setsid ... < /dev/null >> /tmp/*.log 2>&1 &` to daemonize — SSM requires full detachment (append `>>` so logs survive restarts; prepend a `=== timestamp ===` separator line before each run)
- Do NOT use `sudo` inside SSM `AWS-RunShellScript` — SSM already runs as root and `sudo` will hang waiting for a tty
- `ssm_bg` fires a command and returns immediately (fire-and-forget)
- `ssm_run` waits for completion via `aws ssm wait command-executed`
- Git pull uses `sudo -u ec2-user git ...` to avoid SSM's missing `$HOME`
- Routes added: `10.1.2.0/24 via 10.1.1.253 dev eth1` on ClientNIC, `10.1.0.0/24 via 10.1.1.24 dev eth0` on ServerNIC

---

## analyze_capture.py

Validates 0-RTT behavior from pcap files captured on ClientNIC.
Runs **on the ClientNIC VM** (where the pcap files reside).

```bash
python3 integration-test/scripts/analyze_capture.py \
    --client-pcap /tmp/client_side.pcap \
    --server-pcap /tmp/server_side.pcap
```

Exit code: 0 = all checks passed, 1 = one or more failures.

### Checks

**A. Spoofed SYN-ACK Detection**
- Loads all SYN-ACKs from eth0 (client-side) and eth1 (server-side)
- Real ISNs = `{pkt[TCP].seq for pkt in eth1_syn_acks}`
- Spoofed = eth0 SYN-ACKs whose ISN is **not** in the real ISN set
- PASS: at least one spoofed SYN-ACK found on eth0

**B. ISN Delta**
- Matches spoofed and real SYN-ACKs by client dport
- `delta = (spoofed_ISN - real_ISN) & 0xFFFFFFFF`
- PASS: all matched flows have delta != 0

**C. 0-RTT Timing** (informational — does not count as failure)
- Compares timestamps: `t_spoofed < t_real` per flow
- Reports result but does not increment failure count (intra-VPC RTT may be faster than Python/Scapy processing)

**D. Checksum Validation**
- Computes expected IP (RFC 791) and TCP (RFC 793 pseudo-header) checksums
- Compares against on-wire values
- PASS: zero bad checksums on both eth0 and eth1

### Output format

```
[PASS] Real SYN-ACK(s) found on eth1  (2 SYN-ACK(s))
[PASS] Spoofed SYN-ACK(s) found on eth0 (distinct ISN)  (2 spoofed, 0 forwarded-real)
[PASS] All deltas are non-zero  (2 matched flow(s))
[PASS] Spoofed SYN-ACK arrives before real (informational)  (2/2 flows ...)
[PASS] No bad checksums on eth0 (client side)  (all N packets valid)
[PASS] No bad checksums on eth1 (server side)  (all N packets valid)
All checks passed.
```

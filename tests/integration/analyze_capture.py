#!/usr/bin/env python3
"""
Analyze ClientNIC packet captures to validate 0-RTT behavior.

Checks:
  A. 0-RTT Timing   — spoofed SYN-ACK on eth0 arrives before real SYN-ACK on eth1
  B. ISN Delta      — spoofed ISN differs from real ISN; delta is non-zero
  C. Checksums      — no bad IP or TCP checksums on either interface

Runs on the ClientNIC VM where both pcap files reside.

Usage:
    python3 analyze_capture.py \\
        --client-pcap /tmp/client_side.pcap \\
        --server-pcap /tmp/server_side.pcap
"""

import argparse
import socket
import struct
import sys
from typing import List

try:
    from scapy.all import rdpcap, IP, TCP, Ether, raw
    from scapy.utils import checksum as scapy_checksum
except ImportError:
    print("ERROR: scapy not found. Install with: pip3 install scapy", file=sys.stderr)
    sys.exit(2)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(msg, flush=True)


def report(label: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    line = f"[{status}] {label}"
    if detail:
        line += f"  ({detail})"
    log(line)
    return ok


def is_syn_ack(pkt) -> bool:
    """True if packet has both SYN and ACK flags set."""
    return pkt.haslayer(TCP) and bool(pkt[TCP].flags.S) and bool(pkt[TCP].flags.A)


def find_syn_acks(pkts) -> list:
    return [p for p in pkts if p.haslayer(IP) and is_syn_ack(p)]


# ─── Checksum verification ────────────────────────────────────────────────────

def _expected_ip_checksum(pkt) -> int:
    """Compute the expected IP header checksum (RFC 791)."""
    ip = pkt[IP]
    hdr = raw(ip)[: ip.ihl * 4]
    # Zero out the checksum field at bytes 10–11
    hdr_zeroed = hdr[:10] + b"\x00\x00" + hdr[12:]
    return scapy_checksum(hdr_zeroed)


def _expected_tcp_checksum(pkt) -> int:
    """Compute the expected TCP checksum using the pseudo-header (RFC 793)."""
    ip = pkt[IP]
    tcp_raw = raw(pkt[TCP])
    tcp_len = len(tcp_raw)

    pseudo = (
        socket.inet_aton(ip.src)
        + socket.inet_aton(ip.dst)
        + struct.pack("!BBH", 0, 6, tcp_len)
    )
    # Zero out checksum field at bytes 16–17 of TCP header
    tcp_zeroed = tcp_raw[:16] + b"\x00\x00" + tcp_raw[18:]
    return scapy_checksum(pseudo + tcp_zeroed)


def find_bad_checksums(pkts) -> List[str]:
    """Return descriptions of any packets with invalid IP or TCP checksums."""
    bad = []
    for i, pkt in enumerate(pkts, start=1):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        try:
            exp_ip = _expected_ip_checksum(pkt)
            got_ip = pkt[IP].chksum
            if exp_ip != got_ip:
                bad.append(
                    f"pkt#{i} IP  chksum: expected=0x{exp_ip:04x}  got=0x{got_ip:04x}"
                )

            exp_tcp = _expected_tcp_checksum(pkt)
            got_tcp = pkt[TCP].chksum
            if exp_tcp != got_tcp:
                bad.append(
                    f"pkt#{i} TCP chksum: expected=0x{exp_tcp:04x}  got=0x{got_tcp:04x}"
                )
        except Exception as exc:
            bad.append(f"pkt#{i} checksum error: {exc}")
    return bad


# ─── Main analysis ────────────────────────────────────────────────────────────

def analyze(client_pcap: str, server_pcap: str) -> int:
    """Run all checks. Returns number of failures."""
    failures = 0

    # Load captures
    log(f"Loading {client_pcap}  (eth0 — client side)")
    try:
        client_pkts = rdpcap(client_pcap)
    except Exception as exc:
        log(f"[FAIL] Cannot read {client_pcap}: {exc}")
        return 1

    log(f"Loading {server_pcap}  (eth1 — server side)")
    try:
        server_pkts = rdpcap(server_pcap)
    except Exception as exc:
        log(f"[FAIL] Cannot read {server_pcap}: {exc}")
        return 1

    log(f"  eth0: {len(client_pkts)} packet(s)")
    log(f"  eth1: {len(server_pkts)} packet(s)")

    # ── A. 0-RTT Timing ───────────────────────────────────────────────────────
    log("\n-- A. 0-RTT Timing ----------------------------------------------------------")

    client_sas = find_syn_acks(client_pkts)   # spoofed SYN-ACK (sent by ClientNIC)
    server_sas = find_syn_acks(server_pkts)   # real SYN-ACK (from server)

    if not report("Spoofed SYN-ACK found on eth0", bool(client_sas),
                  f"{len(client_sas)} SYN-ACK(s)"):
        failures += 1

    if not report("Real SYN-ACK found on eth1", bool(server_sas),
                  f"{len(server_sas)} SYN-ACK(s)"):
        failures += 1

    spoofed_isn = real_isn = None
    if client_sas and server_sas:
        t_spoofed = float(client_sas[0].time)
        t_real    = float(server_sas[0].time)
        spoofed_isn = client_sas[0][TCP].seq
        real_isn    = server_sas[0][TCP].seq

        log(f"  Spoofed SYN-ACK  time={t_spoofed:.6f}  ISN={spoofed_isn}")
        log(f"  Real    SYN-ACK  time={t_real:.6f}  ISN={real_isn}")

        delta_t = t_real - t_spoofed
        if not report(
            "Spoofed SYN-ACK arrives before real SYN-ACK",
            t_spoofed < t_real,
            f"time delta={delta_t:.3f}s",
        ):
            failures += 1

    # ── B. Sequence Number Delta ───────────────────────────────────────────────
    log("\n-- B. Sequence Number Delta -------------------------------------------------")

    if spoofed_isn is not None and real_isn is not None:
        isns_differ = spoofed_isn != real_isn
        if not report(
            "Spoofed ISN differs from real ISN",
            isns_differ,
            f"spoofed={spoofed_isn}  real={real_isn}",
        ):
            failures += 1

        if isns_differ:
            delta = (spoofed_isn - real_isn) & 0xFFFFFFFF
            log(f"  seq_delta = ({spoofed_isn} - {real_isn}) & 0xFFFFFFFF = {delta}")
            if not report("Delta is non-zero", delta != 0, f"delta={delta}"):
                failures += 1
    else:
        log("[SKIP] ISN delta check — SYN-ACKs not found on both interfaces")
        failures += 1

    # ── C. Checksum Validation ─────────────────────────────────────────────────
    log("\n-- C. Checksum Validation ---------------------------------------------------")

    bad_client = find_bad_checksums(client_pkts)
    bad_server = find_bad_checksums(server_pkts)

    if not report(
        "No bad checksums on eth0 (client side)",
        len(bad_client) == 0,
        f"{len(bad_client)} bad" if bad_client else f"all {len(client_pkts)} packets valid",
    ):
        for line in bad_client[:5]:
            log(f"    {line}")
        failures += 1

    if not report(
        "No bad checksums on eth1 (server side)",
        len(bad_server) == 0,
        f"{len(bad_server)} bad" if bad_server else f"all {len(server_pkts)} packets valid",
    ):
        for line in bad_server[:5]:
            log(f"    {line}")
        failures += 1

    # ── Summary ────────────────────────────────────────────────────────────────
    log(f"\n{'-' * 60}")
    if failures == 0:
        log("All checks passed.")
    else:
        log(f"{failures} check(s) failed.")

    return failures


def main():
    parser = argparse.ArgumentParser(
        description="Validate 0-RTT packet captures from ClientNIC"
    )
    parser.add_argument(
        "--client-pcap",
        default="/tmp/client_side.pcap",
        help="eth0 capture (client side, contains spoofed SYN-ACK)",
    )
    parser.add_argument(
        "--server-pcap",
        default="/tmp/server_side.pcap",
        help="eth1 capture (server side, contains real SYN-ACK)",
    )
    args = parser.parse_args()

    failures = analyze(args.client_pcap, args.server_pcap)
    sys.exit(1 if failures > 0 else 0)


if __name__ == "__main__":
    main()

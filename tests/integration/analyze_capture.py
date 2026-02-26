#!/usr/bin/env python3
"""
Analyze ClientNIC packet captures to validate 0-RTT behavior.

Checks:
  A. Spoofed SYN-ACK    -- ClientNIC sends a SYN-ACK with a random ISN (different
                           from the server's real ISN) on eth0 before (or alongside)
                           the real SYN-ACK that arrives on eth1.
  B. ISN Delta          -- spoofed ISN differs from real ISN; delta is non-zero.
  C. 0-RTT Timing       -- (informational) spoofed SYN-ACK timestamp vs real one.
  D. Checksums          -- no bad IP or TCP checksums on either interface.

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
from typing import List, Dict, Set, Tuple

try:
    from scapy.all import rdpcap, IP, TCP, Ether, raw
    from scapy.utils import checksum as scapy_checksum
except ImportError:
    print("ERROR: scapy not found. Install with: pip3 install scapy", file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Checksum verification
# --------------------------------------------------------------------------- #

def _expected_ip_checksum(pkt) -> int:
    """Compute the expected IP header checksum (RFC 791)."""
    ip = pkt[IP]
    hdr = raw(ip)[: ip.ihl * 4]
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


# --------------------------------------------------------------------------- #
# Main analysis
# --------------------------------------------------------------------------- #

def analyze(client_pcap: str, server_pcap: str) -> int:
    """Run all checks. Returns number of failures."""
    failures = 0

    # Load captures
    log(f"Loading {client_pcap}  (eth0 - client side)")
    try:
        client_pkts = rdpcap(client_pcap)
    except Exception as exc:
        log(f"[FAIL] Cannot read {client_pcap}: {exc}")
        return 1

    log(f"Loading {server_pcap}  (eth1 - server side)")
    try:
        server_pkts = rdpcap(server_pcap)
    except Exception as exc:
        log(f"[FAIL] Cannot read {server_pcap}: {exc}")
        return 1

    log(f"  eth0: {len(client_pkts)} packet(s)")
    log(f"  eth1: {len(server_pkts)} packet(s)")

    # Collect all SYN-ACKs from each interface
    client_sas = find_syn_acks(client_pkts)   # everything on eth0
    server_sas = find_syn_acks(server_pkts)   # everything on eth1

    log(f"\n  eth0 SYN-ACKs: {len(client_sas)}")
    for p in client_sas:
        log(f"    t={float(p.time):.6f}  ISN={p[TCP].seq}  "
            f"{p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport}")
    log(f"\n  eth1 SYN-ACKs: {len(server_sas)}")
    for p in server_sas:
        log(f"    t={float(p.time):.6f}  ISN={p[TCP].seq}  "
            f"{p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport}")

    # --- A. Spoofed SYN-ACK Detection ----------------------------------------
    log("\n-- A. Spoofed SYN-ACK Detection -----------------------------------------")

    # ISNs seen on eth1 = the server's real ISNs
    real_isns: Set[int] = {p[TCP].seq for p in server_sas}

    # Classify eth0 SYN-ACKs: spoofed (ISN not in real set) vs forwarded-real
    spoofed_sas = [p for p in client_sas if p[TCP].seq not in real_isns]
    fwded_sas   = [p for p in client_sas if p[TCP].seq in real_isns]

    log(f"  Real ISNs seen on eth1: {sorted(real_isns)}")
    log(f"  Spoofed SYN-ACKs on eth0 (ISN not in real set): {len(spoofed_sas)}")
    log(f"  Forwarded-real SYN-ACKs on eth0 (ISN in real set): {len(fwded_sas)}")

    if not report("Real SYN-ACK(s) found on eth1", bool(server_sas),
                  f"{len(server_sas)} SYN-ACK(s)"):
        failures += 1

    if not report("Spoofed SYN-ACK(s) found on eth0 (distinct ISN)", bool(spoofed_sas),
                  f"{len(spoofed_sas)} spoofed, {len(fwded_sas)} forwarded-real"):
        failures += 1
        log("  NOTE: spoofed SYN-ACK not detected in eth0 capture.")
        log("        Possible causes: Scapy send() routing issue, kernel dropping packet,")
        log("        or spoofed SYN-ACK arrived but has same ISN as real (collision).")

    # --- B. ISN Delta ---------------------------------------------------------
    log("\n-- B. ISN Delta ---------------------------------------------------------")

    if spoofed_sas and server_sas:
        # Match spoofed SYN-ACK to real SYN-ACK by client port (dport on SYN-ACK)
        real_by_dport: Dict[int, int] = {}
        for p in server_sas:
            real_by_dport[p[TCP].dport] = p[TCP].seq

        matched = []
        for sp in spoofed_sas:
            dport = sp[TCP].dport
            if dport in real_by_dport:
                real_isn = real_by_dport[dport]
                spoofed_isn = sp[TCP].seq
                delta = (spoofed_isn - real_isn) & 0xFFFFFFFF
                matched.append((dport, spoofed_isn, real_isn, delta, float(sp.time)))
                log(f"  flow dport={dport}: spoofed_ISN={spoofed_isn}  real_ISN={real_isn}  "
                    f"delta={delta}")

        if matched:
            all_nonzero = all(delta != 0 for _, _, _, delta, _ in matched)
            if not report("All deltas are non-zero", all_nonzero,
                          f"{len(matched)} matched flow(s)"):
                failures += 1
        else:
            log("[SKIP] No port-matched spoofed/real pair found for delta check")
            failures += 1
    else:
        log("[SKIP] ISN delta check -- need spoofed SYN-ACK on eth0 and real on eth1")
        failures += 1

    # --- C. 0-RTT Timing (informational) --------------------------------------
    log("\n-- C. 0-RTT Timing (informational) -------------------------------------")

    if spoofed_sas and server_sas:
        # Per-flow timing comparison
        real_time_by_dport: Dict[int, float] = {}
        for p in server_sas:
            dport = p[TCP].dport
            t = float(p.time)
            if dport not in real_time_by_dport or t < real_time_by_dport[dport]:
                real_time_by_dport[dport] = t

        timing_ok_count = 0
        timing_total = 0
        for sp in spoofed_sas:
            dport = sp[TCP].dport
            if dport in real_time_by_dport:
                t_spoof = float(sp.time)
                t_real  = real_time_by_dport[dport]
                delta_t = t_real - t_spoof
                ok = t_spoof < t_real
                timing_total += 1
                if ok:
                    timing_ok_count += 1
                log(f"  flow dport={dport}: spoofed_t={t_spoof:.6f}  real_t={t_real:.6f}  "
                    f"delta={delta_t:.3f}s  {'OK (spoofed earlier)' if ok else 'LATE (real faster)'}")

        if timing_total > 0:
            report(
                "Spoofed SYN-ACK arrives before real (informational)",
                timing_ok_count == timing_total,
                f"{timing_ok_count}/{timing_total} flows -- NOTE: intra-VPC RTT may be "
                f"faster than Python/Scapy processing"
            )
            # Timing failure is informational only; don't increment failures
        else:
            log("  [SKIP] No port-matched flows for timing comparison")
    else:
        log("  [SKIP] Timing check -- need both spoofed and real SYN-ACKs")

    # --- D. Checksum Validation -----------------------------------------------
    log("\n-- D. Checksum Validation -----------------------------------------------")

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

    # --- Summary --------------------------------------------------------------
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

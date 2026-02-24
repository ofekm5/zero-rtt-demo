# Plan: Implement ServerNIC

## Context

ServerNIC is the stateless packet forwarder between ClientNIC and Server in the 4-VM 0-RTT chain. Currently only `servernic/docs/serverNIC.md` exists — no implementation code. The spec (written pre-ClientNIC integration testing) uses `sendp()`, but we'll use `send()` from the start since ServerNIC forwards between different subnets (10.1.1.0/24 ↔ 10.1.2.0/24).

## Design Decisions

- **`send()` not `sendp()`**: Cross-subnet forwarding requires kernel routing/ARP (lesson from ClientNIC bug, commit 5d4f6cd)
- **Package structure**: Mirrors `clientnic/` for consistency
- **Stateless**: No flow table, no buffering, no packet modification — just forward based on ingress interface
- **Configurable interfaces**: Default eth1/eth2, overridable via CLI args (useful for local testing)

## Files to Create

```
servernic/
├── __init__.py          # Package marker
├── main.py              # Entry point: arg parsing, logger setup, sniff()
├── forwarder.py         # PacketForwarder class: handle() dispatches by interface
└── logger.py            # setup_logging() — same pattern as clientnic/logger.py
```

## Implementation Details

### `servernic/__init__.py`
One-line package comment, same pattern as `clientnic/__init__.py`.

### `servernic/logger.py`
Copy `clientnic/logger.py` pattern exactly, change logger name from `"clientnic"` to `"servernic"`.

### `servernic/forwarder.py`
```
class PacketForwarder:
    __init__(self, client_iface="eth1", server_iface="eth2")
    handle(self, packet) -> None
        - if not TCP, return
        - determine ingress via packet.sniffed_on
        - if from client_iface → send(packet[IP], iface=server_iface)
        - if from server_iface → send(packet[IP], iface=client_iface)
        - log direction + packet summary (src:port → dst:port [flags])
```

Key details:
- Uses `send(packet[IP], ...)` (Layer 3) — reuse the same import as `clientnic/rewriter.py:5`
- Uses `packet.sniffed_on` to determine ingress interface (Scapy sets this when sniffing on multiple interfaces)
- Logs at INFO level with direction and packet summary
- No checksum recalc needed (no modification)

### `servernic/main.py`
```
def main():
    - parse args: --client-iface (default eth1), --server-iface (default eth2), --verbose
    - setup_logging(DEBUG if verbose else INFO)
    - create PacketForwarder(client_iface, server_iface)
    - log startup with interface names
    - sniff(iface=[client_iface, server_iface], prn=forwarder.handle, filter="tcp", store=False)

if __name__ == "__main__":
    main()
```

Run as: `sudo python3 -m servernic.main` (consistent with ClientNIC: `sudo python3 -m clientnic.main`)

## Update integration-tests.md

Uncomment the ServerNIC step in `.claude/context/plans/integration-tests.md:73-78` with the actual run command:
```bash
cd /home/ec2-user/zero-rtt-demo && sudo python3 -m servernic.main
```

## Unit Tests

### `servernic/test_forwarder.py`
Tests that matter (not trivial):
- `test_handle_forwards_from_client_to_server`: Packet sniffed on eth1 → send() called with server iface
- `test_handle_forwards_from_server_to_client`: Packet sniffed on eth2 → send() called with client iface
- `test_handle_ignores_non_tcp`: Packet without TCP layer → send() not called
- `test_handle_unknown_interface`: Packet from unrecognized interface → send() not called
- `test_custom_interface_names`: Constructor with custom iface names routes correctly

No test_logger.py (we already removed ClientNIC's — same reasoning applies).

## Verification

1. Run unit tests: `pytest servernic/test_forwarder.py -v`
2. Integration test on AWS (manual):
   - Start Server: `cd server-app && sudo python3 server.py --host 0.0.0.0 --port 8080 --verbose`
   - Start ServerNIC: `cd zero-rtt-demo && sudo python3 -m servernic.main`
   - Start ClientNIC: `cd zero-rtt-demo && sudo python3 -m clientnic.main`
   - Run Client: `cd client-app && python3 client.py --host <SERVER_IP> --port 8080 --message "test"`
   - Verify ServerNIC logs show bidirectional forwarding

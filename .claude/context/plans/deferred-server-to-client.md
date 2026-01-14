# Deferred: Server -> Client Functionality

## To Implement Later

### ServerPacketHandler
Handles packets arriving on eth1 from ServerNIC:

1. **SYN-ACK arrives**:
   - Record `real_server_isn` from packet
   - Calculate `seq_delta = spoofed_server_isn - real_server_isn`
   - Update flow state to ESTABLISHED
   - Drop the packet (client already has spoofed SYN-ACK)
   - Flush buffered packets (rewrite and forward to eth1)

2. **DATA arrives**:
   - Lookup flow by reverse key (swap src/dst)
   - Rewrite ACK: `ack = (ack - delta) & 0xFFFFFFFF`
   - Recalculate checksums
   - Forward to eth0 (client)

### Required Changes

- Add `ServerPacketHandler` class to `handlers.py`
- Update `PacketRouter` to route eth1 packets
- Add `extract_reverse_key()` to FlowTable
- Update `main.py` sniff to include eth1

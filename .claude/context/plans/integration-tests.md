# Manual Integration Tests

## Step 1: Connect via SSM and Start Components (in order)

### Server VM (i-06e33c323814811d0) - IP: 10.1.0.137
```bash
# Connect to Server VM
aws ssm start-session --target i-06e33c323814811d0

# Run server
cd /home/ec2-user/zero-rtt-demo/server-app && sudo python3 server.py --host 0.0.0.0 --port 8080 --verbose
```

### ServerNIC VM (not implemented yet - skip)
```bash
# cd /home/ec2-user/zero-rtt-demo/servernic && sudo python3 main.py --iface-to-client eth1 --iface-to-server eth2
```

### ClientNIC VM (i-0c1cc148d595ae510) - IP: 10.1.0.104
```bash
# Connect to ClientNIC VM
aws ssm start-session --target i-0c1cc148d595ae510

# Run ClientNIC
cd /home/ec2-user/zero-rtt-demo && sudo python3 -m clientnic.main
```

### Client VM (i-0159ce30abff0881b) - IP: 10.1.0.10
```bash
# Connect to Client VM
aws ssm start-session --target i-0159ce30abff0881b

# Run client (target server IP: 10.1.0.137)
cd /home/ec2-user/zero-rtt-demo/client-app && python3 client.py --host 10.1.0.137 --port 8080 --message "Hello 0-RTT"
```

## Step 2: Verify Basic Connectivity

### Check connection established
```bash
# On Server VM
ss -tn state established | grep 8080
```

### Check data received
Server should print received message. Client should print response.

## Step 3: Verify 0-RTT Behavior

### Capture packets on ClientNIC (eth0 - client side)
```bash
# On ClientNIC VM - run before client connects
sudo tcpdump -i eth0 -nn -tttt 'tcp port 8080' -w /tmp/client_side.pcap
```

### Capture packets on ClientNIC (eth1 - server side)
```bash
# On ClientNIC VM - separate terminal
sudo tcpdump -i eth1 -nn -tttt 'tcp port 8080' -w /tmp/server_side.pcap
```

### Analyze captures
```bash
# View packets with timestamps
tcpdump -nn -tttt -r /tmp/client_side.pcap

# Expected sequence:
# 1. SYN from client (eth0)
# 2. SYN-ACK to client (eth0) <-- SPOOFED, immediate
# 3. ACK from client (eth0)
# 4. DATA from client (eth0)
# ... later ...
# 5. Real SYN-ACK from server (eth1) <-- arrives after spoofed one
```

## Step 4: Verify Sequence Number Translation

### Check flow table state
```bash
# On ClientNIC VM (if debug endpoint exists)
curl http://localhost:9999/flows

# Or check logs
cat /tmp/clientnic.log | grep "delta"
```

### Verify in packet capture
```bash
# Compare SEQ numbers on eth0 vs eth1
tcpdump -nn -r /tmp/client_side.pcap 'tcp[tcpflags] & tcp-syn != 0'
tcpdump -nn -r /tmp/server_side.pcap 'tcp[tcpflags] & tcp-syn != 0'

# The SYN-ACK SEQ on eth0 (spoofed) should differ from eth1 (real)
# Delta = spoofed_seq - real_seq
```

## Step 5: Verify Checksums

```bash
# Wireshark/tshark validation
tshark -r /tmp/client_side.pcap -Y "tcp.checksum_bad==1"

# Should return empty (no bad checksums)
```

## Quick Smoke Test

Run all at once after components are started:
```bash
# On Client VM - send 5 requests, measure time
for i in {1..5}; do
  time python client.py --host <SERVER_IP> --port 8080 --message "test $i"
done
```

## Expected Success Criteria

| Check | Expected |
|-------|----------|
| Client receives response | Yes |
| Server receives correct data | Yes |
| Spoofed SYN-ACK timestamp < real SYN-ACK | Yes |
| No checksum errors | Yes |
| Flow table shows delta calculated | Yes |

## Troubleshooting

### No packets captured
```bash
# Check interface names
ip link show

# Verify tcpdump filter
sudo tcpdump -i eth0 -nn tcp
```

### Connection refused
```bash
# Check server is listening
ss -tlnp | grep 8080

# Check security groups allow traffic
```

### Packets not forwarded
```bash
# Check IP forwarding enabled
cat /proc/sys/net/ipv4/ip_forward
# Should be 1

# Enable if needed
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

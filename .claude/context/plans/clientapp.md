# Client VM — Integration Test Runbook

Run this entirely on the **Client VM**. Every cross-VM dependency is preceded by a `[WAIT]` block.

---

## Step 0: Export Instance ID and Server IP

Run from your **local machine** before connecting.

```bash
export CLIENT_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-client" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

export SERVER_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)

echo "Client: $CLIENT_ID"
echo "Server IP: $SERVER_IP"
```

---

> **[WAIT]** Confirm ClientNIC is running (`clientnic.main`) before continuing.
> ServerNIC and the Server should already be up as well.
>
> **Press Enter to continue.**

---

## Step 1: Connect via SSM

```bash
aws ssm start-session --target $CLIENT_ID
```

---

## Step 2: Run a Single Client Request

```bash
cd /home/ec2-user/zero-rtt-demo/client-app
python3 client.py --host $SERVER_IP --port 8080 --message "Hello 0-RTT"
```

The client should print the server's response, e.g.:

```
Connected to <SERVER_IP>:8080
Sent: Hello 0-RTT
Received: Echo: Hello 0-RTT
```

---

> **[WAIT]** Did the client print a response?
>
> - **Yes** → continue to Step 3.
> - **No** → go to Troubleshooting below before continuing.

---

## Step 3: Quick Smoke Test — 5 Requests with Timing

```bash
for i in {1..5}; do
  time python3 client.py --host $SERVER_IP --port 8080 --message "test $i"
done
```

Review the `real` time for each request. With 0-RTT, time-to-first-byte should be reduced by approximately 1 RTT compared to a standard TCP handshake.

---

## Expected Success Criteria

| Check | Expected |
|-------|----------|
| Client receives response | Yes |
| Server receives correct data | Yes |
| Spoofed SYN-ACK timestamp < real SYN-ACK | Yes |
| No checksum errors in captures | Yes |
| Flow table shows delta calculated | Yes |

---

## Troubleshooting

### Connection refused

```bash
# Confirm the server IP is correct
echo $SERVER_IP

# Check server is listening (run on Server VM)
ss -tlnp | grep 8080

# Check ClientNIC and ServerNIC are running and forwarding packets
```

### Client hangs / no response

```bash
# Verify ClientNIC is intercepting and not stuck
# Check clientnic.main output on ClientNIC VM

# Check security groups allow TCP port 8080 between VMs
```

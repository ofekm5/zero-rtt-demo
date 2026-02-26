# Server VM — Integration Test Runbook

Run this entirely on the **Server VM**. Every cross-VM dependency is preceded by a `[WAIT]` block.

---

## Step 0: Export Instance ID and IP

Run from your **local machine** before connecting.

```bash
export SERVER_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

export SERVER_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)

echo "Server: $SERVER_ID ($SERVER_IP)"
```

---

## Step 1: Connect via SSM and Start the Server

```bash
aws ssm start-session --target $SERVER_ID
```

Once connected:

```bash
cd /home/ec2-user/zero-rtt-demo/server-app
sudo python3 server.py --host 0.0.0.0 --port 8080 --verbose
```

The server should print something like:

```
Listening on 0.0.0.0:8080...
```

Leave this running in the foreground.

---

> **[WAIT]** Switch to the other runbooks and bring up ServerNIC, ClientNIC, and the Client in order.
> Come back here once the client test has been sent.
>
> **Press Enter to continue verification.**

---

## Step 2: Verify Connection Established

In a second SSM session to the Server VM:

```bash
ss -tn state established | grep 8080
```

Expected output: at least one row showing an established connection to port 8080.

---

## Step 3: Verify Data Received

Check the server console (the window running `server.py`). You should see:

- The received message (e.g., `Received: Hello 0-RTT`)
- Confirmation that a response was sent back to the client

If `--verbose` is set, the full payload and client address will be printed.

---

## Troubleshooting

### Server not listening / connection refused

```bash
# Confirm server process is running
ss -tlnp | grep 8080

# If not running, restart
cd /home/ec2-user/zero-rtt-demo/server-app
sudo python3 server.py --host 0.0.0.0 --port 8080 --verbose
```

### No connection established

```bash
# Check security groups allow inbound TCP on port 8080
# Check that ClientNIC and ServerNIC are running
# Verify server IP matches what the client is targeting
echo $SERVER_IP
```

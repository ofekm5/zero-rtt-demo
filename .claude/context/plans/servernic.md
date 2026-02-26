# ServerNIC VM — Integration Test Runbook

Run this entirely on the **ServerNIC VM**. Every cross-VM dependency is preceded by a `[WAIT]` block.

---

## Step 0: Export Instance ID

Run from your **local machine** before connecting.

```bash
export SERVERNIC_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=smartnics-servernic" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

echo "ServerNIC: $SERVERNIC_ID"
```

---

> **[WAIT]** Confirm the Server VM is running `server.py` and listening on port 8080 before continuing.
>
> **Press Enter to continue.**

---

## Step 1: Connect via SSM

```bash
aws ssm start-session --target $SERVERNIC_ID
```

---

## Step 2: Start ServerNIC

```bash
cd /home/ec2-user/zero-rtt-demo
sudo python3 -m servernic.main
```

ServerNIC is a stateless forwarder. It should print something like:

```
Listening on eth1 (ClientNIC side) and eth2 (Server side)...
```

Leave this running in the foreground.

---

> **[WAIT]** Switch to the ClientNIC and Client runbooks and complete the client test run.
> Come back here once the client has sent at least one request.
>
> **Press Enter to verify forwarding.**

---

## Step 3: Verify Packets Were Forwarded

Open a second SSM session to the ServerNIC VM and check the logs:

```bash
# If servernic writes logs
cat /tmp/servernic.log

# Or inspect live traffic that was forwarded
sudo tcpdump -i eth1 -nn 'tcp port 8080' -c 20
sudo tcpdump -i eth2 -nn 'tcp port 8080' -c 20
```

Expected: packets visible on both interfaces, indicating bidirectional forwarding.

---

## Troubleshooting

### IP forwarding not enabled

```bash
cat /proc/sys/net/ipv4/ip_forward
# Should be 1

# Enable if needed
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Wrong interface names

```bash
# List interfaces to confirm eth1/eth2 names
ip link show

# Adjust servernic/main.py if interface names differ (e.g., ens5, enp0s3)
```

### Packets arriving on one side but not forwarded

```bash
# Check that servernic.main is still running
ps aux | grep servernic

# Restart if needed
cd /home/ec2-user/zero-rtt-demo
sudo python3 -m servernic.main
```

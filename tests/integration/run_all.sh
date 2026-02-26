#!/usr/bin/env bash
# Full end-to-end integration test for the 0-RTT TCP demo.
# Orchestrates all 4 VMs via AWS SSM in the correct startup order:
#   Server → ServerNIC → ClientNIC → Client
#
# Prerequisites (run locally):
#   - aws CLI configured with credentials that have SSM access
#   - python3 in PATH
#
# Usage:
#   ./tests/integration/run_all.sh
#
# Exit code: 0 = all checks passed, non-zero = number of failures

set -uo pipefail

REPO_PATH="/home/ec2-user/zero-rtt-demo"
SERVER_PORT=8080

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

FAILURES=0

log()  { echo -e "${YELLOW}[$(date '+%H:%M:%S')] $*${NC}" >&2; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILURES=$((FAILURES + 1)); }

# Build SSM parameters JSON from a shell command string
mk_params() { python3 -c "import json,sys; print(json.dumps({'commands':[sys.argv[1]]}))" "$1"; }
# Extract element N from a JSON array on stdin
json_idx()  { python3 -c "import json,sys; print(json.load(sys.stdin)[$1], end='')"; }


# ─── Dependency checks ────────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
    echo "ERROR: aws CLI is required" >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi


# ─── SSM helpers ──────────────────────────────────────────────────────────────

# ssm_run <instance-id> <command> [timeout-sec]
# Runs a command synchronously via SSM.
# Returns JSON array: [Status, Stdout, Stderr]
ssm_run() {
    local iid="$1" cmd="$2" timeout="${3:-120}"
    local params cid

    params=$(mk_params "$cmd")

    cid=$(aws ssm send-command \
        --instance-ids "$iid" \
        --document-name "AWS-RunShellScript" \
        --parameters "$params" \
        --timeout-seconds "$timeout" \
        --query "Command.CommandId" \
        --output text)

    # Wait until the command finishes (Success or Failed)
    aws ssm wait command-executed \
        --command-id "$cid" \
        --instance-id "$iid" 2>/dev/null || true

    aws ssm get-command-invocation \
        --command-id "$cid" \
        --instance-id "$iid" \
        --query "[Status, StandardOutputContent, StandardErrorContent]" \
        --output json
}

# ssm_stdout <instance-id> <command> [timeout-sec]
# Like ssm_run but returns only stdout text.
ssm_stdout() {
    ssm_run "$1" "$2" "${3:-120}" | json_idx 1
}

# ssm_bg <instance-id> <command>
# Fires a command in the background on the VM and returns immediately.
# The command must daemonize itself (nohup ... &).
ssm_bg() {
    local iid="$1" cmd="$2"
    local params
    params=$(mk_params "$cmd")
    aws ssm send-command \
        --instance-ids "$iid" \
        --document-name "AWS-RunShellScript" \
        --parameters "$params" \
        --timeout-seconds 30 \
        --query "Command.CommandId" \
        --output text > /dev/null
}


# ─── EC2 discovery ────────────────────────────────────────────────────────────

get_iid() {
    aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$1" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].InstanceId" \
        --output text
}

get_ip() {
    aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$1" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].PrivateIpAddress" \
        --output text
}


# ─── Step 0: Discover instances ───────────────────────────────────────────────
log "Step 0: Discovering EC2 instances..."

SERVER_ID=$(get_iid "smartnics-server")
SERVERNIC_ID=$(get_iid "smartnics-servernic")
CLIENTNIC_ID=$(get_iid "smartnics-clientnic")
CLIENT_ID=$(get_iid "smartnics-client")
SERVER_IP=$(get_ip "smartnics-server")

log "  Server:    $SERVER_ID  ($SERVER_IP)"
log "  ServerNIC: $SERVERNIC_ID"
log "  ClientNIC: $CLIENTNIC_ID"
log "  Client:    $CLIENT_ID"

for var in SERVER_ID SERVERNIC_ID CLIENTNIC_ID CLIENT_ID SERVER_IP; do
    val="${!var}"
    if [[ -z "$val" || "$val" == "None" ]]; then
        echo -e "${RED}ERROR: could not find running instance for $var${NC}" >&2
        exit 1
    fi
done


# ─── Pull latest code on all VMs ──────────────────────────────────────────────
log "Pulling latest code on all VMs..."
for iid in "$SERVER_ID" "$SERVERNIC_ID" "$CLIENTNIC_ID" "$CLIENT_ID"; do
    # SSM runs as root without $HOME; use sudo -u ec2-user to avoid git config errors
    ssm_bg "$iid" "sudo -u ec2-user git -C $REPO_PATH pull origin main 2>&1 || true"
done
sleep 8   # give git pulls time to complete


# ─── Cleanup any leftover processes ───────────────────────────────────────────
log "Cleaning up previous runs..."
ssm_bg "$SERVER_ID"    "pkill -f 'python3.*server.py' 2>/dev/null; rm -f /tmp/server.log"
ssm_bg "$SERVERNIC_ID" "pkill -f 'python3.*servernic' 2>/dev/null; rm -f /tmp/servernic.log"
ssm_bg "$CLIENTNIC_ID" "pkill -f 'python3.*clientnic' 2>/dev/null; pkill tcpdump 2>/dev/null; rm -f /tmp/clientnic.log /tmp/client_side.pcap /tmp/server_side.pcap"
sleep 3


# ─── Step 1: Start Server ─────────────────────────────────────────────────────
log "Step 1: Starting Server..."
# setsid detaches from SSM's process group so the daemon outlives the SSM command
ssm_bg "$SERVER_ID" \
    "cd $REPO_PATH/server-app && setsid python3 -u server.py --host 0.0.0.0 --port $SERVER_PORT --verbose < /dev/null > /tmp/server.log 2>&1 &"
sleep 2

LISTEN_CHECK=$(ssm_stdout "$SERVER_ID" "ss -tlnp | grep $SERVER_PORT && echo LISTENING || echo NOT_LISTENING" 30)
if echo "$LISTEN_CHECK" | grep -q "LISTENING"; then
    pass "Server listening on :$SERVER_PORT"
else
    fail "Server not listening on :$SERVER_PORT"
    echo "  ss output: $LISTEN_CHECK"
fi


# ─── Step 2: Start ServerNIC ──────────────────────────────────────────────────
log "Step 2: Starting ServerNIC..."
# Enable IP forwarding and add VM-level route for return path before starting Scapy
ssm_run "$SERVERNIC_ID" "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward" 30 > /dev/null
ssm_run "$SERVERNIC_ID" \
    "ip route replace 10.1.0.0/24 via 10.1.1.24 dev eth0 2>&1 || true" 30 > /dev/null
ssm_bg "$SERVERNIC_ID" \
    "cd $REPO_PATH && setsid python3 -u -m servernic.main < /dev/null > /tmp/servernic.log 2>&1 &"
sleep 2

FWRD=$(ssm_stdout "$SERVERNIC_ID" "cat /proc/sys/net/ipv4/ip_forward" 30)
if [[ "$FWRD" == "1" ]]; then
    pass "ServerNIC: IP forwarding enabled"
else
    fail "ServerNIC: IP forwarding NOT enabled (got '$FWRD')"
fi


# ─── Step 3: Start ClientNIC + packet captures ────────────────────────────────
log "Step 3: Starting ClientNIC + packet captures..."

# Enable IP forwarding and add VM-level route so Scapy send() uses eth1→ServerNIC
ssm_run "$CLIENTNIC_ID" "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward" 30 > /dev/null
ssm_run "$CLIENTNIC_ID" \
    "ip route replace 10.1.2.0/24 via 10.1.1.253 dev eth1 2>&1 || true" 30 > /dev/null

# Start captures BEFORE clientnic so we catch the very first SYN
ssm_bg "$CLIENTNIC_ID" \
    "setsid tcpdump -i eth0 -nn -tttt 'tcp port $SERVER_PORT' -w /tmp/client_side.pcap < /dev/null > /tmp/tcpdump_eth0.log 2>&1 &"
ssm_bg "$CLIENTNIC_ID" \
    "setsid tcpdump -i eth1 -nn -tttt 'tcp port $SERVER_PORT' -w /tmp/server_side.pcap < /dev/null > /tmp/tcpdump_eth1.log 2>&1 &"
sleep 1

ssm_bg "$CLIENTNIC_ID" \
    "cd $REPO_PATH && setsid python3 -u -m clientnic.main < /dev/null > /tmp/clientnic.log 2>&1 &"
sleep 2

FWRD=$(ssm_stdout "$CLIENTNIC_ID" "cat /proc/sys/net/ipv4/ip_forward" 30)
if [[ "$FWRD" == "1" ]]; then
    pass "ClientNIC: IP forwarding enabled"
else
    fail "ClientNIC: IP forwarding NOT enabled (got '$FWRD')"
fi


# ─── Step 4: Run client test ──────────────────────────────────────────────────
log "Step 4: Running client test (3 connections)..."
CLIENT_RESULT=$(ssm_run "$CLIENT_ID" \
    "cd $REPO_PATH/client-app && python3 client.py --host $SERVER_IP --port $SERVER_PORT --mode repeated --count 3 --verbose" \
    60)

CLIENT_STDOUT=$(echo "$CLIENT_RESULT" | json_idx 1)
CLIENT_STDERR=$(echo "$CLIENT_RESULT"  | json_idx 2)

echo "--- Client output ---"
echo "$CLIENT_STDOUT"
[[ -n "$CLIENT_STDERR" ]] && echo "stderr: $CLIENT_STDERR"
echo "---------------------"

if echo "$CLIENT_STDOUT" | grep -qE "Success: 3/3|100%"; then
    pass "All 3 client connections succeeded"
else
    fail "Not all client connections succeeded"
fi

# Allow tcpdump to flush final packets before we stop it
sleep 3


# ─── Step 5: Stop captures ────────────────────────────────────────────────────
log "Step 5: Stopping packet captures..."
ssm_run "$CLIENTNIC_ID" "pkill tcpdump 2>/dev/null || true; sleep 1" 30 > /dev/null
pass "tcpdump stopped"


# ─── Step 6: Verify server received data ──────────────────────────────────────
log "Step 6: Verifying server received data..."
SERVER_LOG=$(ssm_stdout "$SERVER_ID" "cat /tmp/server.log" 30)
echo "--- Server log ---"
echo "$SERVER_LOG"
echo "------------------"

if echo "$SERVER_LOG" | grep -qiE "Received|bytes"; then
    pass "Server received data from client"
else
    fail "Server log shows no received data"
fi


# ─── Step 7: Check ClientNIC flow table ───────────────────────────────────────
log "Step 7: Checking ClientNIC flow table activity..."
CLIENTNIC_LOG=$(ssm_stdout "$CLIENTNIC_ID" "cat /tmp/clientnic.log" 30)
echo "--- ClientNIC log ---"
echo "$CLIENTNIC_LOG"
echo "---------------------"

if echo "$CLIENTNIC_LOG" | grep -qiE "delta|flow created|syn received|spoofed"; then
    pass "ClientNIC: flow table entries seen in log"
else
    fail "ClientNIC: no flow table activity in log"
fi


# ─── Step 8: Analyze packet captures ──────────────────────────────────────────
log "Step 8: Running packet capture analysis..."

# Show pcap sizes for diagnostics
PCAP_SIZES=$(ssm_stdout "$CLIENTNIC_ID" \
    "ls -lh /tmp/client_side.pcap /tmp/server_side.pcap 2>&1 || echo 'pcap files not found'" 30)
echo "pcap files: $PCAP_SIZES"

# Upload analyze_capture.py to the VM via base64 (avoids dependency on git push)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANALYZE_B64=$(python3 -c "import base64; print(base64.b64encode(open('$SCRIPT_DIR/analyze_capture.py','rb').read()).decode())")
ssm_run "$CLIENTNIC_ID" "echo '$ANALYZE_B64' | base64 -d > /tmp/analyze_capture.py" 30 > /dev/null
log "  analyze_capture.py uploaded to ClientNIC"

ANALYSIS_RESULT=$(ssm_run "$CLIENTNIC_ID" \
    "python3 /tmp/analyze_capture.py \
        --client-pcap /tmp/client_side.pcap \
        --server-pcap /tmp/server_side.pcap" \
    45)

ANALYSIS_STATUS=$(echo "$ANALYSIS_RESULT" | json_idx 0)
ANALYSIS_STDOUT=$(echo "$ANALYSIS_RESULT" | json_idx 1)
ANALYSIS_STDERR=$(echo "$ANALYSIS_RESULT" | json_idx 2)

echo "--- Packet analysis (status: $ANALYSIS_STATUS) ---"
echo "$ANALYSIS_STDOUT"
[[ -n "$ANALYSIS_STDERR" ]] && echo "stderr: $ANALYSIS_STDERR"
echo "-----------------------"

if [[ "$ANALYSIS_STATUS" == "Success" ]] && echo "$ANALYSIS_STDOUT" | grep -q "All checks passed"; then
    pass "Packet capture analysis: all checks passed"
else
    NFAIL=$(printf '%s' "$ANALYSIS_STDOUT" | grep -c '\[FAIL\]' || true)
    fail "Packet capture analysis: $NFAIL check(s) failed (status=$ANALYSIS_STATUS)"
fi


# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}  ALL CHECKS PASSED${NC}"
else
    echo -e "${RED}  $FAILURES CHECK(S) FAILED${NC}"
fi
echo "════════════════════════════════════════"

exit "$FAILURES"

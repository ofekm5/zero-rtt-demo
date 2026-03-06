#!/usr/bin/env bash
# destroy.sh - Tear down the SmartNICs CDK stacks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Safety prompt unless --force is passed
if [[ "${1:-}" != "--force" ]]; then
    echo "WARNING: This will destroy all SmartNICs infrastructure (4 EC2 instances, VPC, subnets, etc.)"
    read -r -p "Are you sure? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

echo "[*] Destroying SmartNicsStack..."
cdk destroy SmartNicsStack --force

echo "[*] Destroying PacketTestStack..."
cdk destroy PacketTestStack --force

# Clean up local key file if it exists
KEY_FILE="$SCRIPT_DIR/smartnics-key.pem"
if [[ -f "$KEY_FILE" ]]; then
    rm -f "$KEY_FILE"
    echo "[+] Removed local SSH key: $KEY_FILE"
fi

echo "[+] Destroy complete."

#!/usr/bin/env bash
# deploy.sh - Deploy the SmartNICs CDK stacks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Install CDK dependencies if needed
if ! python3 -c "import aws_cdk" 2>/dev/null; then
    echo "[*] Installing CDK dependencies..."
    pip3 install -r requirements.txt
fi

# Bootstrap if requested
if [[ "${1:-}" == "--bootstrap" ]]; then
    echo "[*] Bootstrapping CDK environment..."
    cdk bootstrap
    shift
fi

echo "[*] Deploying PacketTestStack and SmartNicsStack..."
cdk deploy --all --require-approval never "$@"

echo ""
echo "[*] Retrieving SSH key from SSM..."
KEY_PARAM=$(aws cloudformation describe-stacks \
    --stack-name SmartNicsStack \
    --query "Stacks[0].Outputs[?OutputKey=='KeyPairParameterName'].OutputValue" \
    --output text \
    --region eu-central-1)

if [[ -n "$KEY_PARAM" ]]; then
    KEY_FILE="$SCRIPT_DIR/smartnics-key.pem"
    aws ssm get-parameter \
        --name "$KEY_PARAM" \
        --with-decryption \
        --query Parameter.Value \
        --output text \
        --region eu-central-1 > "$KEY_FILE"
    chmod 400 "$KEY_FILE"
    echo "[+] SSH key saved to: $KEY_FILE"
fi

echo ""
echo "[+] Deploy complete. Stack outputs:"
aws cloudformation describe-stacks \
    --stack-name SmartNicsStack \
    --query "Stacks[0].Outputs[*].[OutputKey,OutputValue]" \
    --output table \
    --region eu-central-1

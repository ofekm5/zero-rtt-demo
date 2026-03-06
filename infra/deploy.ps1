# deploy.ps1 - Deploy the SmartNICs CDK stacks
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [string[]]$CdkArgs = @()
)
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
Push-Location $ScriptDir

try {
    # Install CDK dependencies if needed
    $null = python -c "import aws_cdk" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[*] Installing CDK dependencies..."
        pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { exit 1 }
    }

    # Bootstrap if requested
    if ($Bootstrap) {
        Write-Host "[*] Bootstrapping CDK environment..."
        cdk bootstrap
        if ($LASTEXITCODE -ne 0) { exit 1 }
    }

    Write-Host "[*] Deploying PacketTestStack and SmartNicsStack..."
    cdk deploy --all --require-approval never @CdkArgs
    if ($LASTEXITCODE -ne 0) { exit 1 }

    Write-Host ""
    Write-Host "[*] Retrieving SSH key from SSM..."
    $KeyParam = aws cloudformation describe-stacks `
        --stack-name SmartNicsStack `
        --query "Stacks[0].Outputs[?OutputKey=='KeyPairParameterName'].OutputValue" `
        --output text `
        --region eu-central-1
    if ($LASTEXITCODE -ne 0) { exit 1 }

    if ($KeyParam) {
        $KeyFile = Join-Path $ScriptDir "smartnics-key.pem"
        aws ssm get-parameter `
            --name $KeyParam `
            --with-decryption `
            --query Parameter.Value `
            --output text `
            --region eu-central-1 | Set-Content -Path $KeyFile -NoNewline
        if ($LASTEXITCODE -ne 0) { exit 1 }
        Write-Host "[+] SSH key saved to: $KeyFile"
    }

    Write-Host ""
    Write-Host "[+] Deploy complete. Stack outputs:"
    aws cloudformation describe-stacks `
        --stack-name SmartNicsStack `
        --query "Stacks[0].Outputs[*].[OutputKey,OutputValue]" `
        --output table `
        --region eu-central-1

} finally {
    Pop-Location
}

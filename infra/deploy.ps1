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
    # Create venv if it doesn't exist
    $VenvDir = Join-Path $ScriptDir ".venv"
    if (-not (Test-Path $VenvDir)) {
        Write-Host "[*] Creating virtual environment..."
        python -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { exit 1 }
    }

    # Activate venv
    $Activate = Join-Path $VenvDir "Scripts\Activate.ps1"
    . $Activate

    # Install CDK dependencies if needed
    python -c "import aws_cdk" 2>&1 | Out-Null
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
    Write-Host "[+] Deploy complete. Stack outputs:"
    aws cloudformation describe-stacks `
        --stack-name SmartNicsStack `
        --query "Stacks[0].Outputs[*].[OutputKey,OutputValue]" `
        --output table `
        --region eu-central-1

} finally {
    Pop-Location
}

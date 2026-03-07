# destroy.ps1 - Tear down the SmartNICs CDK stacks
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Force
)
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
Push-Location $ScriptDir

try {
    # Use the shared repo-root venv
    $VenvDir = Join-Path $ScriptDir "..\venv"
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

    # Safety prompt unless -Force is passed
    if (-not $Force) {
        Write-Host "WARNING: This will destroy all SmartNICs infrastructure (4 EC2 instances, VPC, subnets, etc.)"
        $Confirm = Read-Host "Are you sure? [y/N]"
        if ($Confirm -notmatch '^[Yy]$') {
            Write-Host "Aborted."
            exit 0
        }
    }

    Write-Host "[*] Destroying SmartNicsStack..."
    cdk destroy SmartNicsStack --force
    if ($LASTEXITCODE -ne 0) { exit 1 }

    Write-Host "[*] Destroying PacketTestStack..."
    cdk destroy PacketTestStack --force
    if ($LASTEXITCODE -ne 0) { exit 1 }

    Write-Host "[+] Destroy complete."

} finally {
    Pop-Location
}

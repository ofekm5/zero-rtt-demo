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
    # Activate venv
    $Activate = Join-Path $ScriptDir ".venv\Scripts\Activate.ps1"
    if (-not (Test-Path $Activate)) {
        Write-Host "[-] No virtual environment found. Run deploy.ps1 first to set it up."
        exit 1
    }
    . $Activate

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

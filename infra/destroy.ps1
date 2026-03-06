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

    # Clean up local key file if it exists
    $KeyFile = Join-Path $ScriptDir "smartnics-key.pem"
    if (Test-Path $KeyFile) {
        Remove-Item $KeyFile -Force
        Write-Host "[+] Removed local SSH key: $KeyFile"
    }

    Write-Host "[+] Destroy complete."

} finally {
    Pop-Location
}

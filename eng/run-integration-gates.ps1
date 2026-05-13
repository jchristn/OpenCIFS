param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & powershell -ExecutionPolicy Bypass -File $ScriptPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$commonArguments = @(
    "-Configuration", $Configuration,
    "-Framework", $Framework
)

Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "test.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-managed-interop.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-published-sample-smoke.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-real-client-interop.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-samba-interop.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-windows-client-interop.ps1") -Arguments $commonArguments

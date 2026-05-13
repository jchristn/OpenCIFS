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

function Get-EnvironmentVariableValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    return [Environment]::GetEnvironmentVariable($Name)
}

function Invoke-OptionalWindowsServerInterop {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $requiredEnvironmentVariables = @(
        "OPENCIFS_WINDOWS_SERVER_NAME",
        "OPENCIFS_WINDOWS_SERVER_SHARE_NAME",
        "OPENCIFS_WINDOWS_SERVER_USER_NAME",
        "OPENCIFS_WINDOWS_SERVER_PASSWORD"
    )

    $configuredVariables = @(
        $requiredEnvironmentVariables |
            Where-Object { -not [string]::IsNullOrWhiteSpace((Get-EnvironmentVariableValue -Name $_)) }
    )

    if ($configuredVariables.Count -eq 0) {
        Write-Host "Skipping optional Windows-server interop because OPENCIFS_WINDOWS_SERVER_* is not configured."
        return
    }

    $missingVariables = @(
        $requiredEnvironmentVariables |
            Where-Object { [string]::IsNullOrWhiteSpace((Get-EnvironmentVariableValue -Name $_)) }
    )

    if ($missingVariables.Count -ne 0) {
        throw "Optional Windows-server interop is partially configured. Set or clear all of: $($requiredEnvironmentVariables -join ', '). Missing: $($missingVariables -join ', ')."
    }

    Write-Host "Running optional Windows-server interop against the configured live Windows SMB share."
    Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-windows-server-interop.ps1") -Arguments $Arguments
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
Invoke-OptionalWindowsServerInterop -Arguments $commonArguments

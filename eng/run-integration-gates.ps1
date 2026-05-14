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

function Test-EnabledEnvironmentFlag {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = Get-EnvironmentVariableValue -Name $Name
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $false
    }

    switch ($value.Trim().ToLowerInvariant()) {
        "1" { return $true }
        "true" { return $true }
        "yes" { return $true }
        "on" { return $true }
        "0" { return $false }
        "false" { return $false }
        "no" { return $false }
        "off" { return $false }
        default {
            throw "Environment flag '$Name' must be one of: true, false, 1, 0, yes, no, on, off."
        }
    }
}

function Invoke-OptionalCrossVersionManagedInterop {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    if (-not (Test-EnabledEnvironmentFlag -Name "OPENCIFS_ENABLE_CROSS_VERSION_INTEROP")) {
        Write-Host "Skipping optional cross-version managed interop because OPENCIFS_ENABLE_CROSS_VERSION_INTEROP is not enabled."
        return
    }

    $sharedVersion = Get-EnvironmentVariableValue -Name "OPENCIFS_CROSS_VERSION_PACKAGE_VERSION"
    $clientVersion = Get-EnvironmentVariableValue -Name "OPENCIFS_PREVIOUS_CLIENT_PACKAGE_VERSION"
    $serverVersion = Get-EnvironmentVariableValue -Name "OPENCIFS_PREVIOUS_SERVER_PACKAGE_VERSION"

    if ([string]::IsNullOrWhiteSpace($clientVersion)) {
        $clientVersion = $sharedVersion
    }

    if ([string]::IsNullOrWhiteSpace($serverVersion)) {
        $serverVersion = $sharedVersion
    }

    if ([string]::IsNullOrWhiteSpace($clientVersion) -or [string]::IsNullOrWhiteSpace($serverVersion)) {
        throw "Optional cross-version managed interop is enabled, but the previous package versions are not fully configured. Set OPENCIFS_CROSS_VERSION_PACKAGE_VERSION or both OPENCIFS_PREVIOUS_CLIENT_PACKAGE_VERSION and OPENCIFS_PREVIOUS_SERVER_PACKAGE_VERSION."
    }

    $crossVersionArguments = New-Object System.Collections.Generic.List[string]
    foreach ($argument in $Arguments) {
        $crossVersionArguments.Add($argument)
    }

    $packageSource = Get-EnvironmentVariableValue -Name "OPENCIFS_CROSS_VERSION_PACKAGE_SOURCE"
    if (-not [string]::IsNullOrWhiteSpace($packageSource)) {
        $crossVersionArguments.Add("-PackageSource")
        $crossVersionArguments.Add($packageSource)
    }

    Write-Host "Running optional cross-version managed interop against the configured previous package versions."
    Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-cross-version-managed-interop.ps1") -Arguments $crossVersionArguments
}

function Invoke-OptionalLinuxCifsInterop {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    if (-not (Test-EnabledEnvironmentFlag -Name "OPENCIFS_ENABLE_LINUX_CIFS_INTEROP")) {
        Write-Host "Skipping optional Linux CIFS interop because OPENCIFS_ENABLE_LINUX_CIFS_INTEROP is not enabled."
        return
    }

    $linuxCifsArguments = New-Object System.Collections.Generic.List[string]
    foreach ($argument in $Arguments) {
        $linuxCifsArguments.Add($argument)
    }

    $imageName = Get-EnvironmentVariableValue -Name "OPENCIFS_LINUX_CIFS_IMAGE_NAME"
    if (-not [string]::IsNullOrWhiteSpace($imageName)) {
        $linuxCifsArguments.Add("-ImageName")
        $linuxCifsArguments.Add($imageName)
    }

    Write-Host "Running optional Linux CIFS interop against Sample.OpenCifsServer."
    Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-linux-cifs-interop.ps1") -Arguments $linuxCifsArguments
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
Invoke-OptionalCrossVersionManagedInterop -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-published-sample-smoke.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-real-client-interop.ps1") -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-samba-interop.ps1") -Arguments $commonArguments
Invoke-OptionalLinuxCifsInterop -Arguments $commonArguments
Invoke-ChildPowerShellScript -ScriptPath (Join-Path $PSScriptRoot "run-windows-client-interop.ps1") -Arguments $commonArguments
Invoke-OptionalWindowsServerInterop -Arguments $commonArguments

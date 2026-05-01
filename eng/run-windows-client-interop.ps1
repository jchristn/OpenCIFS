param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [int]$Port = 0,
    [string]$DriveLetter = "Z:",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [int]$LargePayloadLength = 200000
)

$ErrorActionPreference = "Stop"

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the deeper Windows interop path exercises bounded large-I/O behavior."
}

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$MaximumAttempts = 1,
        [int]$RetryDelaySeconds = 5
    )

    $lastExitCode = 0
    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        $childOutput = & powershell -ExecutionPolicy Bypass -File $ScriptPath @Arguments
        $lastExitCode = $LASTEXITCODE

        if ($null -ne $childOutput) {
            @($childOutput) | ForEach-Object { Write-Host $_ }
        }

        if ($lastExitCode -eq 0) {
            return
        }

        if ($attempt -lt $MaximumAttempts) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    throw "Windows interop child script '$ScriptPath' exited with code $lastExitCode."
}

function Test-DialectWorkflowSucceeded {
    param(
        [Parameter(Mandatory = $true)][string]$WorkflowPath
    )

    if (-not (Test-Path -LiteralPath $WorkflowPath)) {
        throw "Expected Windows interop workflow artifact '$WorkflowPath' was not produced."
    }

    $workflow = Get-Content -Path $WorkflowPath -Raw | ConvertFrom-Json

    if ($null -eq $workflow.final_state) {
        throw "Windows interop workflow artifact '$WorkflowPath' does not contain a final_state payload."
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$workflow.final_state.failure)) {
        throw "Windows interop workflow artifact '$WorkflowPath' recorded a failure: $($workflow.final_state.failure)"
    }

    if ($null -eq $workflow.mapping) {
        throw "Windows interop workflow artifact '$WorkflowPath' did not record a successful mapped-drive snapshot."
    }

    return $workflow
}

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                RemoteHost = "localhost"
                ShareName = "share2002"
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                RemoteHost = "localhost"
                ShareName = "share21"
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                RemoteHost = "localhost"
                ShareName = "share302"
            }
        }
        default {
            throw "Unsupported dialect '$Dialect'."
        }
    }
}

function Get-DriveLetterForIndex {
    param(
        [Parameter(Mandatory = $true)][string]$BaseDriveLetter,
        [Parameter(Mandatory = $true)][int]$Index
    )

    $trimmed = $BaseDriveLetter.TrimEnd(':')

    if ($trimmed.Length -ne 1) {
        throw "DriveLetter must be a single drive-letter designator such as 'Z:'."
    }

    $baseValue = [int][char]$trimmed[0]
    $candidateValue = $baseValue - $Index

    if ($candidateValue -lt [int][char]'D') {
        throw "Not enough distinct drive letters are available to run the requested Windows interop dialect matrix."
    }

    return ([char]$candidateValue).ToString() + ":"
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\windows-client-interop"
$combinedConfigurationPath = Join-Path $artifactRoot "sample-server.config.txt"
$combinedEnvironmentPath = Join-Path $artifactRoot "windows-client-environment.json"
$combinedWorkflowPath = Join-Path $artifactRoot "windows-client-smoke.json"
$combinedServerLogPath = Join-Path $artifactRoot "sample-server.log"
$combinedServerErrorPath = Join-Path $artifactRoot "sample-server.err.log"
$singleRunScriptPath = Join-Path $PSScriptRoot "run-windows-client-interop-single.ps1"

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
Set-Content -Path $combinedConfigurationPath -Value ""
Set-Content -Path $combinedServerLogPath -Value ""
Set-Content -Path $combinedServerErrorPath -Value ""

$runs = New-Object System.Collections.Generic.List[object]
$sharedEnvironment = $null

for ($dialectIndex = 0; $dialectIndex -lt $Dialects.Length; $dialectIndex++) {
    $dialect = $Dialects[$dialectIndex]
    $dialectMetadata = Get-DialectMetadata -Dialect $dialect
    $dialectDriveLetter = Get-DriveLetterForIndex -BaseDriveLetter $DriveLetter -Index $dialectIndex
    $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
    $dialectConfigurationPath = Join-Path $dialectArtifactRoot "sample-server.config.txt"
    $dialectEnvironmentPath = Join-Path $dialectArtifactRoot "windows-client-environment.json"
    $dialectWorkflowPath = Join-Path $dialectArtifactRoot "windows-client-smoke.json"
    $dialectServerLogPath = Join-Path $dialectArtifactRoot "sample-server.log"
    $dialectServerErrorPath = Join-Path $dialectArtifactRoot "sample-server.err.log"

    Invoke-ChildPowerShellScript -ScriptPath $singleRunScriptPath -MaximumAttempts 3 -RetryDelaySeconds 5 -Arguments @(
        "-Configuration", $Configuration,
        "-Framework", $Framework,
        "-Port", $Port.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        "-DriveLetter", $dialectDriveLetter,
        "-Dialect", $dialectMetadata.Dialect,
        "-ArtifactSubdirectory", $dialectMetadata.DialectId,
        "-RemoteHost", $dialectMetadata.RemoteHost,
        "-ShareName", $dialectMetadata.ShareName,
        "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    )

    Start-Sleep -Seconds 1
    $dialectWorkflow = Test-DialectWorkflowSucceeded -WorkflowPath $dialectWorkflowPath

    Add-Content -Path $combinedConfigurationPath -Value ("==== " + $dialectMetadata.Label + " ====")
    Get-Content -Path $dialectConfigurationPath | Add-Content -Path $combinedConfigurationPath
    Add-Content -Path $combinedConfigurationPath -Value ""
    Add-Content -Path $combinedServerLogPath -Value ("==== " + $dialectMetadata.Label + " ====")
    Get-Content -Path $dialectServerLogPath | Add-Content -Path $combinedServerLogPath
    Add-Content -Path $combinedServerLogPath -Value ""
    Add-Content -Path $combinedServerErrorPath -Value ("==== " + $dialectMetadata.Label + " ====")
    Get-Content -Path $dialectServerErrorPath | Add-Content -Path $combinedServerErrorPath
    Add-Content -Path $combinedServerErrorPath -Value ""

    if ($null -eq $sharedEnvironment) {
        $sharedEnvironment = Get-Content -Path $dialectEnvironmentPath -Raw | ConvertFrom-Json
    }

    $runs.Add($dialectWorkflow)
    Start-Sleep -Seconds 1
}

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    common_environment = $sharedEnvironment
    runs = $runs
} | ConvertTo-Json -Depth 10 | Set-Content -Path $combinedWorkflowPath -Encoding UTF8

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    dialects = $Dialects
    environment = $sharedEnvironment
} | ConvertTo-Json -Depth 6 | Set-Content -Path $combinedEnvironmentPath -Encoding UTF8

Write-Host "Windows SMB client interop smoke completed. Evidence:"
Write-Host "  $combinedWorkflowPath"
Write-Host "  $combinedEnvironmentPath"
Write-Host "  $combinedConfigurationPath"
Write-Host "  $combinedServerLogPath"
Write-Host "  $combinedServerErrorPath"

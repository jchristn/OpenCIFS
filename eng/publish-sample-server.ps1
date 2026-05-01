param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectPath = Join-Path $repositoryRoot "src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repositoryRoot "artifacts\published-sample-server"
}
else {
    $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
}

$publishRoot = Join-Path $OutputRoot "publish"
$manifestPath = Join-Path $OutputRoot "sample-server-manifest.json"
$configurationPath = Join-Path $publishRoot "sample.opencifs.server.json"
$configurationReportPath = Join-Path $OutputRoot "sample-server.config.txt"
$quickstartPath = Join-Path $OutputRoot "sample-server-quickstart.txt"
$launcherPath = Join-Path $publishRoot "run-sample-server.ps1"
$printLauncherPath = Join-Path $publishRoot "print-sample-server-config.ps1"
$validateLauncherPath = Join-Path $publishRoot "validate-sample-server-config.ps1"

if (Test-Path $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $publishRoot -Force | Out-Null

dotnet publish $projectPath --configuration $Configuration --framework $Framework --no-restore --output $publishRoot
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$publishedExecutablePath = Join-Path $publishRoot "Sample.OpenCifsServer.exe"
$publishedAssemblyPath = Join-Path $publishRoot "Sample.OpenCifsServer.dll"

if (Test-Path $publishedExecutablePath) {
    $invocationMode = "native"
}
elseif (Test-Path $publishedAssemblyPath) {
    $invocationMode = "dotnet"
}
else {
    throw "Could not locate a published Sample.OpenCifsServer executable or assembly in $publishRoot."
}

function Invoke-PublishedSampleServer {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$CapturePath = ""
    )

    if ([string]::IsNullOrWhiteSpace($CapturePath)) {
        if ($invocationMode -eq "native") {
            & $publishedExecutablePath @Arguments
        }
        else {
            & dotnet $publishedAssemblyPath @Arguments
        }
    }
    else {
        if ($invocationMode -eq "native") {
            & $publishedExecutablePath @Arguments | Tee-Object -FilePath $CapturePath | Out-Null
        }
        else {
            & dotnet $publishedAssemblyPath @Arguments | Tee-Object -FilePath $CapturePath | Out-Null
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Published Sample.OpenCifsServer invocation failed."
    }
}

Invoke-PublishedSampleServer -Arguments @("--config", $configurationPath, "--write-default-config")
Invoke-PublishedSampleServer -Arguments @("--config", $configurationPath, "--print-config") -CapturePath $configurationReportPath

$launcherInvocation = if ($invocationMode -eq "native") {
    '& (Join-Path $PSScriptRoot "Sample.OpenCifsServer.exe") "--config" $configPath @args'
}
else {
    '& dotnet (Join-Path $PSScriptRoot "Sample.OpenCifsServer.dll") "--config" $configPath @args'
}

$launcherLines = @(
    '$ErrorActionPreference = "Stop"',
    '$configPath = Join-Path $PSScriptRoot "sample.opencifs.server.json"',
    $launcherInvocation,
    'exit $LASTEXITCODE'
)

$printLauncherLines = @(
    '$ErrorActionPreference = "Stop"',
    '$launcherPath = Join-Path $PSScriptRoot "run-sample-server.ps1"',
    '& powershell -ExecutionPolicy Bypass -File $launcherPath "--print-config"',
    'exit $LASTEXITCODE'
)

$validateLauncherLines = @(
    '$ErrorActionPreference = "Stop"',
    '$launcherPath = Join-Path $PSScriptRoot "run-sample-server.ps1"',
    '& powershell -ExecutionPolicy Bypass -File $launcherPath "--validate-config"',
    'exit $LASTEXITCODE'
)

Set-Content -Path $launcherPath -Value $launcherLines -Encoding UTF8
Set-Content -Path $printLauncherPath -Value $printLauncherLines -Encoding UTF8
Set-Content -Path $validateLauncherPath -Value $validateLauncherLines -Encoding UTF8

$quickstartLines = @(
    'OpenCIFS published sample server bundle',
    '',
    'Run the sample server with the default generated configuration:',
    '  powershell -ExecutionPolicy Bypass -File .\publish\run-sample-server.ps1',
    '',
    'Print the effective configuration:',
    '  powershell -ExecutionPolicy Bypass -File .\publish\print-sample-server-config.ps1',
    '',
    'Validate the generated configuration without starting the listener:',
    '  powershell -ExecutionPolicy Bypass -File .\publish\validate-sample-server-config.ps1',
    '',
    'The default configuration file lives at:',
    '  ' + $configurationPath,
    '',
    'The default share root resolves to:',
    '  ' + (Join-Path $publishRoot 'SampleShare')
)
Set-Content -Path $quickstartPath -Value $quickstartLines -Encoding UTF8

[pscustomobject]@{
    GeneratedAtUtc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    Configuration = $Configuration
    Framework = $Framework
    OutputRoot = $OutputRoot
    PublishRoot = $publishRoot
    InvocationMode = $invocationMode
    ExecutablePath = if (Test-Path $publishedExecutablePath) { $publishedExecutablePath } else { $null }
    AssemblyPath = if (Test-Path $publishedAssemblyPath) { $publishedAssemblyPath } else { $null }
    ConfigurationPath = $configurationPath
    ConfigurationReportPath = $configurationReportPath
    LauncherPath = $launcherPath
    PrintLauncherPath = $printLauncherPath
    ValidateLauncherPath = $validateLauncherPath
    QuickstartPath = $quickstartPath
} | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "Published Sample.OpenCifsServer bundle completed. Artifacts:"
Write-Host "  $manifestPath"
Write-Host "  $launcherPath"
Write-Host "  $configurationReportPath"

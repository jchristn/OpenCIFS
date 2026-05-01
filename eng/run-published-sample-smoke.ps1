param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21")
)

$ErrorActionPreference = "Stop"

function Wait-ServerReady {
    param(
        [System.Diagnostics.Process]$Process,
        [int]$TcpPort,
        [string]$ServerLogPath,
        [string]$ServerErrorPath
    )

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500

        if ($Process.HasExited) {
            throw "The published Sample.OpenCifsServer bundle exited before the port opened. See $ServerLogPath and $ServerErrorPath."
        }

        $tcpClient = New-Object System.Net.Sockets.TcpClient

        try {
            $tcpClient.Connect("127.0.0.1", $TcpPort)
            $tcpClient.Close()
            return
        }
        catch {
        }
        finally {
            $tcpClient.Dispose()
        }
    }

    throw "Timed out waiting for the published Sample.OpenCifsServer bundle to open 127.0.0.1:$TcpPort."
}

function Resolve-AvailableTcpPort {
    param(
        [int]$PreferredPort,
        [int]$MaximumAttempts = 32
    )

    if ($PreferredPort -le 0) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)

        try {
            $listener.Start()
            return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        }
        finally {
            $listener.Stop()
        }
    }

    for ($offset = 0; $offset -lt $MaximumAttempts; $offset++) {
        $candidatePort = $PreferredPort + $offset
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $candidatePort)

        try {
            $listener.Start()
            return $candidatePort
        }
        catch [System.Net.Sockets.SocketException] {
        }
        finally {
            if ($null -ne $listener.Server) {
                $listener.Stop()
            }
        }
    }

    throw "Could not find an available loopback TCP port after trying $MaximumAttempts port(s) starting at $PreferredPort."
}

function Invoke-PublishedSampleServer {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$CapturePath = ""
    )

    $processArguments = @("--config", [string]$Manifest.ConfigurationPath) + $Arguments

    if ([string]::Equals([string]$Manifest.InvocationMode, "native", [System.StringComparison]::OrdinalIgnoreCase)) {
        if ([string]::IsNullOrWhiteSpace($CapturePath)) {
            & ([string]$Manifest.ExecutablePath) @processArguments
        }
        else {
            & ([string]$Manifest.ExecutablePath) @processArguments | Tee-Object -FilePath $CapturePath | Out-Null
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($CapturePath)) {
            & dotnet ([string]$Manifest.AssemblyPath) @processArguments
        }
        else {
            & dotnet ([string]$Manifest.AssemblyPath) @processArguments | Tee-Object -FilePath $CapturePath | Out-Null
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "The published Sample.OpenCifsServer invocation failed."
    }
}

function Start-PublishedSampleServerProcess {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Manifest,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ServerLogPath,
        [Parameter(Mandatory = $true)][string]$ServerErrorPath
    )

    if ([string]::Equals([string]$Manifest.InvocationMode, "native", [System.StringComparison]::OrdinalIgnoreCase)) {
        return Start-Process `
            -FilePath ([string]$Manifest.ExecutablePath) `
            -ArgumentList (@("--config", [string]$Manifest.ConfigurationPath) + $Arguments) `
            -WorkingDirectory ([string]$Manifest.PublishRoot) `
            -WindowStyle Hidden `
            -RedirectStandardOutput $ServerLogPath `
            -RedirectStandardError $ServerErrorPath `
            -PassThru
    }

    return Start-Process `
        -FilePath "dotnet" `
        -ArgumentList (@([string]$Manifest.AssemblyPath, "--config", [string]$Manifest.ConfigurationPath) + $Arguments) `
        -WorkingDirectory ([string]$Manifest.PublishRoot) `
        -WindowStyle Hidden `
        -RedirectStandardOutput $ServerLogPath `
        -RedirectStandardError $ServerErrorPath `
        -PassThru
}

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                PythonDialect = "smb2002"
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                PythonDialect = "smb21"
            }
        }
        default {
            throw "Unsupported dialect '$Dialect'."
        }
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\published-sample-smoke"
$bundleRoot = Join-Path $repositoryRoot "artifacts\published-sample-server"
$combinedSmokePath = Join-Path $artifactRoot "published-sample-smoke.json"
$combinedConfigurationPath = Join-Path $artifactRoot "sample-server.config.txt"
$defaultValidationPath = Join-Path $artifactRoot "sample-server.validation.txt"
$venvRoot = Join-Path $artifactRoot ".venv"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "publish-sample-server.ps1") `
    -Configuration $Configuration `
    -Framework $Framework `
    -OutputRoot $bundleRoot
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$manifestPath = Join-Path $bundleRoot "sample-server-manifest.json"
$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
if (-not (Test-Path $venvRoot)) {
    python -m venv $venvRoot
}

$venvPython = Join-Path $venvRoot "Scripts\python.exe"
& $venvPython -m pip install --disable-pip-version-check smbprotocol==1.16.1 | Out-Null

& ([string]$manifest.ValidateLauncherPath) | Tee-Object -FilePath $defaultValidationPath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to validate the default published Sample.OpenCifsServer configuration."
}

Get-Content -Path $manifest.ConfigurationReportPath | Set-Content -Path $combinedConfigurationPath -Encoding UTF8

$results = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $dialectMetadata = Get-DialectMetadata -Dialect $dialect
    $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
    $dialectShareRoot = Join-Path $dialectArtifactRoot "share"
    $dialectServerLogPath = Join-Path $dialectArtifactRoot "sample-server.log"
    $dialectServerErrorPath = Join-Path $dialectArtifactRoot "sample-server.err.log"
    $dialectSmokePath = Join-Path $dialectArtifactRoot "published-sample-smoke.json"
    $dialectConfigurationPath = Join-Path $dialectArtifactRoot "sample-server.config.txt"
    $dialectPort = Resolve-AvailableTcpPort -PreferredPort 0

    if (Test-Path $dialectArtifactRoot) {
        Remove-Item -LiteralPath $dialectArtifactRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $dialectArtifactRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $dialectShareRoot | Out-Null

    $sampleServerArguments = @(
        "--print-config",
        "--server-name", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--bind-port", $dialectPort.ToString(),
        "--share-name", "share",
        "--share-path", $dialectShareRoot,
        "--minimum-dialect", $dialectMetadata.Dialect,
        "--maximum-dialect", $dialectMetadata.Dialect,
        "--require-signing", "true",
        "--require-ntlmv2", "true",
        "--allow-anonymous", "false",
        "--enable-smb1", "false",
        "--require-encryption-for-smb3", "false",
        "--account-username", "alice",
        "--account-domain", "WORKGROUP",
        "--account-password", "Password123!"
    )

    Invoke-PublishedSampleServer -Manifest $manifest -Arguments $sampleServerArguments -CapturePath $dialectConfigurationPath

    $serverArguments = @(
        "--server-name", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--bind-port", $dialectPort.ToString(),
        "--share-name", "share",
        "--share-path", $dialectShareRoot,
        "--minimum-dialect", $dialectMetadata.Dialect,
        "--maximum-dialect", $dialectMetadata.Dialect,
        "--require-signing", "true",
        "--require-ntlmv2", "true",
        "--allow-anonymous", "false",
        "--enable-smb1", "false",
        "--require-encryption-for-smb3", "false",
        "--account-username", "alice",
        "--account-domain", "WORKGROUP",
        "--account-password", "Password123!"
    )

    $serverProcess = Start-PublishedSampleServerProcess `
        -Manifest $manifest `
        -Arguments $serverArguments `
        -ServerLogPath $dialectServerLogPath `
        -ServerErrorPath $dialectServerErrorPath

    try {
        Wait-ServerReady -Process $serverProcess -TcpPort $dialectPort -ServerLogPath $dialectServerLogPath -ServerErrorPath $dialectServerErrorPath

        & $venvPython `
            (Join-Path $PSScriptRoot "real-client-smoke.py") `
            --server 127.0.0.1 `
            --port $dialectPort `
            --share share `
            --username alice `
            --password Password123! `
            --domain WORKGROUP `
            --dialect $dialectMetadata.PythonDialect `
            --large-payload-length 200000 `
            | Tee-Object -FilePath $dialectSmokePath

        if ($LASTEXITCODE -ne 0) {
            throw "The published sample-server smoke run failed for $($dialectMetadata.Label)."
        }

        $result = Get-Content -Path $dialectSmokePath -Raw | ConvertFrom-Json
        $results.Add([pscustomobject]@{
            dialect_id = $dialectMetadata.DialectId
            dialect = $dialectMetadata.Label
            configuration_path = $dialectConfigurationPath
            server_log_path = $dialectServerLogPath
            server_error_path = $dialectServerErrorPath
            summary = $result
        })
    }
    finally {
        if (-not $serverProcess.HasExited) {
            Stop-Process -Id $serverProcess.Id -Force
            $serverProcess.WaitForExit()
        }
    }
}

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    publish_manifest_path = $manifestPath
    launcher_path = $manifest.LauncherPath
    print_launcher_path = $manifest.PrintLauncherPath
    validate_launcher_path = $manifest.ValidateLauncherPath
    quickstart_path = $manifest.QuickstartPath
    runs = $results
} | ConvertTo-Json -Depth 8 | Set-Content -Path $combinedSmokePath -Encoding UTF8

Write-Host "Published Sample.OpenCifsServer smoke completed. Evidence:"
Write-Host "  $combinedSmokePath"
Write-Host "  $combinedConfigurationPath"

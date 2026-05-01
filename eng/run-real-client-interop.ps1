param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [int]$Port = 0,
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [int]$LargePayloadLength = 200000
)

$ErrorActionPreference = "Stop"

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the deeper interop path exercises bounded large-I/O behavior."
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

function Stop-StaleSampleServerProcesses {
    param([string]$ProjectPath)

    $staleProcesses = Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "dotnet.exe" -and
            $null -ne $_.CommandLine -and
            $_.CommandLine -like ("*" + $ProjectPath + "*")
        } |
        Select-Object -ExpandProperty ProcessId

    foreach ($processId in $staleProcesses) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $processId -ErrorAction SilentlyContinue
    }
}

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
            throw "Sample.OpenCifsServer exited before the port opened. See $ServerLogPath and $ServerErrorPath."
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

    throw "Timed out waiting for Sample.OpenCifsServer to open 127.0.0.1:$TcpPort."
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
                RequireEncryptionForSmb3 = $false
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                PythonDialect = "smb21"
                RequireEncryptionForSmb3 = $false
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                PythonDialect = "smb302"
                RequireEncryptionForSmb3 = $true
            }
        }
        default {
            throw "Unsupported dialect '$Dialect'."
        }
    }
}

$artifactRoot = Join-Path $PSScriptRoot "..\artifacts\real-client-interop"
$combinedConfigurationPath = Join-Path $artifactRoot "sample-server.config.txt"
$combinedSmokeLogPath = Join-Path $artifactRoot "real-client-smoke.json"
$venvRoot = Join-Path $artifactRoot ".venv"

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
Set-Content -Path $combinedConfigurationPath -Value ""

if (-not (Test-Path $venvRoot)) {
    python -m venv $venvRoot
}

$venvPython = Join-Path $venvRoot "Scripts\python.exe"
& $venvPython -m pip install --disable-pip-version-check smbprotocol==1.16.1 | Out-Null

$projectPath = Join-Path $PSScriptRoot "..\src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"
Stop-StaleSampleServerProcesses -ProjectPath $projectPath

$results = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $dialectMetadata = Get-DialectMetadata -Dialect $dialect
    $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
    $shareRoot = Join-Path $dialectArtifactRoot "share"
    $printedConfigurationPath = Join-Path $dialectArtifactRoot "sample-server.config.txt"
    $serverLogPath = Join-Path $dialectArtifactRoot "sample-server.log"
    $serverErrorPath = Join-Path $dialectArtifactRoot "sample-server.err.log"
    $smokeLogPath = Join-Path $dialectArtifactRoot "real-client-smoke.json"

    New-Item -ItemType Directory -Force -Path $dialectArtifactRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $shareRoot | Out-Null

    if (Test-Path $shareRoot) {
        Get-ChildItem -Path $shareRoot -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    $Port = Resolve-AvailableTcpPort -PreferredPort $Port

    $sampleServerArguments = @(
        "--server-name", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--bind-port", $Port.ToString(),
        "--share-name", "share",
        "--share-path", $shareRoot,
        "--minimum-dialect", $dialectMetadata.Dialect,
        "--maximum-dialect", $dialectMetadata.Dialect,
        "--require-signing", "true",
        "--require-ntlmv2", "true",
        "--allow-anonymous", "false",
        "--enable-smb1", "false",
        "--require-encryption-for-smb3", $dialectMetadata.RequireEncryptionForSmb3.ToString().ToLowerInvariant(),
        "--account-username", "alice",
        "--account-domain", "WORKGROUP",
        "--account-password", "Password123!"
    )
    $printArguments = @(
        "run",
        "--project", $projectPath,
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build",
        "--",
        "--print-config"
    ) + $sampleServerArguments

    & dotnet $printArguments | Tee-Object -FilePath $printedConfigurationPath | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to print the effective Sample.OpenCifsServer configuration for $($dialectMetadata.Label)."
    }

    Add-Content -Path $combinedConfigurationPath -Value ("==== " + $dialectMetadata.Label + " ====")
    Get-Content -Path $printedConfigurationPath | Add-Content -Path $combinedConfigurationPath
    Add-Content -Path $combinedConfigurationPath -Value ""

    $serverArguments = @(
        "run",
        "--project", $projectPath,
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build",
        "--"
    ) + $sampleServerArguments

    $serverProcess = Start-Process `
        -FilePath "dotnet" `
        -ArgumentList $serverArguments `
        -WorkingDirectory (Join-Path $PSScriptRoot "..") `
        -WindowStyle Hidden `
        -RedirectStandardOutput $serverLogPath `
        -RedirectStandardError $serverErrorPath `
        -PassThru

    try {
        Wait-ServerReady -Process $serverProcess -TcpPort $Port -ServerLogPath $serverLogPath -ServerErrorPath $serverErrorPath

        & $venvPython `
            (Join-Path $PSScriptRoot "real-client-smoke.py") `
            --server 127.0.0.1 `
            --port $Port `
            --share share `
            --username alice `
            --password Password123! `
            --domain WORKGROUP `
            --dialect $dialectMetadata.PythonDialect `
            --large-payload-length $LargePayloadLength `
            | Tee-Object -FilePath $smokeLogPath

        if ($LASTEXITCODE -ne 0) {
            throw "The real SMB client smoke run failed for $($dialectMetadata.Label)."
        }

        $result = Get-Content -Path $smokeLogPath -Raw | ConvertFrom-Json
        $results.Add([pscustomobject]@{
            dialect_id = $dialectMetadata.DialectId
            dialect = $dialectMetadata.Label
            config_path = $printedConfigurationPath
            server_log_path = $serverLogPath
            server_error_path = $serverErrorPath
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
    runs = $results
} | ConvertTo-Json -Depth 8 | Set-Content -Path $combinedSmokeLogPath -Encoding UTF8

Write-Host "Real SMB client interop smoke completed. Evidence:"
Write-Host "  $combinedSmokeLogPath"
Write-Host "  $combinedConfigurationPath"

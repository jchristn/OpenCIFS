param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

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
        [int]$TcpPort
    )

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500

        if ($Process.HasExited) {
            throw "Sample.OpenCifsServer exited before the port opened. See $serverLogPath and $serverErrorPath."
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

$artifactRoot = Join-Path $PSScriptRoot "..\artifacts\real-client-interop"
$shareRoot = Join-Path $artifactRoot "share"
$venvRoot = Join-Path $artifactRoot ".venv"
$printedConfigurationPath = Join-Path $artifactRoot "sample-server.config.txt"
$serverLogPath = Join-Path $artifactRoot "sample-server.log"
$serverErrorPath = Join-Path $artifactRoot "sample-server.err.log"
$smokeLogPath = Join-Path $artifactRoot "real-client-smoke.json"

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
New-Item -ItemType Directory -Force -Path $shareRoot | Out-Null

if (-not (Test-Path $venvRoot)) {
    python -m venv $venvRoot
}

$venvPython = Join-Path $venvRoot "Scripts\python.exe"
& $venvPython -m pip install --disable-pip-version-check smbprotocol==1.16.1 | Out-Null

$projectPath = Join-Path $PSScriptRoot "..\src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"
$Port = Resolve-AvailableTcpPort -PreferredPort $Port
Stop-StaleSampleServerProcesses -ProjectPath $projectPath
$sampleServerArguments = @(
    "--server-name", "127.0.0.1",
    "--bind-address", "127.0.0.1",
    "--bind-port", $Port.ToString(),
    "--share-name", "share",
    "--share-path", $shareRoot,
    "--minimum-dialect", "Smb21",
    "--maximum-dialect", "Smb21",
    "--require-signing", "true",
    "--require-ntlmv2", "true",
    "--allow-anonymous", "false",
    "--enable-smb1", "false",
    "--require-encryption-for-smb3", "false",
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
    throw "Failed to print the effective Sample.OpenCifsServer configuration."
}

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
    Wait-ServerReady -Process $serverProcess -TcpPort $Port

    & $venvPython `
        (Join-Path $PSScriptRoot "real-client-smoke.py") `
        --server 127.0.0.1 `
        --port $Port `
        --share share `
        --username alice `
        --password Password123! `
        --domain WORKGROUP `
        --large-payload-length 200000 `
        | Tee-Object -FilePath $smokeLogPath

    if ($LASTEXITCODE -ne 0) {
        throw "The real SMB client smoke run failed."
    }
}
finally {
    if (-not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}

Write-Host "Real SMB client interop smoke completed. Evidence:"
Write-Host "  $smokeLogPath"
Write-Host "  $printedConfigurationPath"
Write-Host "  $serverLogPath"
Write-Host "  $serverErrorPath"

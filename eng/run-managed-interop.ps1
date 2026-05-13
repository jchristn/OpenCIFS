param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302")
)

$ErrorActionPreference = "Stop"

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\managed-interop"
$resultPath = Join-Path $artifactRoot "managed-interop.json"
$shareName = "public"
$userName = "tester"
$password = "Password123!"
$echoPipeName = "opencifs.echo"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)

    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-ForConsoleOutput {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedText,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        if ($Process.HasExited) {
            break
        }

        if (Test-Path $Path) {
            $content = Get-Content -Path $Path -Raw
            if (-not [string]::IsNullOrEmpty($content) -and $content.Contains($ExpectedText)) {
                return $true
            }
        }

        Start-Sleep -Milliseconds 250
    }

    return $false
}

function Assert-OutputContains {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedText
    )

    $content = Get-Content -Path $Path -Raw
    if (-not $content.Contains($ExpectedText)) {
        throw "Expected '$ExpectedText' in $Path."
    }
}

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                RequireEncryption = $false
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                RequireEncryption = $false
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                RequireEncryption = $true
            }
        }
        default {
            throw "Unsupported managed interop dialect '$Dialect'."
        }
    }
}

function Invoke-ManagedInteropRun {
    param(
        [Parameter(Mandatory = $true)]$DialectMetadata
    )

    $runRoot = Join-Path $artifactRoot $DialectMetadata.DialectId
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

    $serverInputPath = Join-Path $runRoot "server-input.txt"
    $clientInputPath = Join-Path $runRoot "client-input.txt"
    $serverOutputPath = Join-Path $runRoot "server-output.txt"
    $serverErrorPath = Join-Path $runRoot "server-error.txt"
    $clientOutputPath = Join-Path $runRoot "client-output.txt"
    $clientErrorPath = Join-Path $runRoot "client-error.txt"
    $downloadPath = Join-Path $runRoot "download.txt"
    $expectedText = "Hello from OpenCIFS managed interop " + $DialectMetadata.DialectId
    $expectedPipeText = "Hello from OpenCIFS managed interop pipe " + $DialectMetadata.DialectId
    $port = Get-FreeTcpPort
    $encryptionSwitch = if ($DialectMetadata.RequireEncryption) { "on" } else { "off" }

    @(
        "server 127.0.0.1",
        "bind 127.0.0.1",
        "port $port",
        "share $shareName",
        "user $userName",
        "password $password",
        "dialects $($DialectMetadata.Dialect) $($DialectMetadata.Dialect)",
        "signing on",
        "encryption $encryptionSwitch",
        "start",
        "wait 60",
        "q"
    ) | Out-File -FilePath $serverInputPath -Encoding ascii

    @(
        "server 127.0.0.1",
        "port $port",
        "user $userName",
        "password $password",
        "dialects $($DialectMetadata.Dialect) $($DialectMetadata.Dialect)",
        "signing on",
        "encryption $encryptionSwitch",
        "connect",
        "status",
        "shares",
        "shareinfo $shareName",
        "pipe $echoPipeName $expectedPipeText",
        "open $shareName",
        "mkdir /docs",
        "write-text /docs/hello.txt $expectedText",
        "ls /docs",
        "stat /docs/hello.txt",
        "cat /docs/hello.txt",
        "mv /docs/hello.txt /docs/renamed.txt",
        ("get /docs/renamed.txt """ + $downloadPath + """"),
        "rm /docs/renamed.txt",
        "rmdir /docs",
        "close",
        "disconnect",
        "q"
    ) | Out-File -FilePath $clientInputPath -Encoding ascii

    $serverArguments = @(
        "run",
        "--project", "src/OpenCIFS.TestServer/OpenCIFS.TestServer.csproj",
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build"
    )

    $clientArguments = @(
        "run",
        "--project", "src/OpenCIFS.TestClient/OpenCIFS.TestClient.csproj",
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build"
    )

    $serverProcess = $null
    $clientProcess = $null

    try {
        $serverProcess = Start-Process `
            -FilePath "dotnet" `
            -ArgumentList $serverArguments `
            -WorkingDirectory $repositoryRoot `
            -RedirectStandardInput $serverInputPath `
            -RedirectStandardOutput $serverOutputPath `
            -RedirectStandardError $serverErrorPath `
            -WindowStyle Hidden `
            -PassThru

        $started = Wait-ForConsoleOutput -Process $serverProcess -Path $serverOutputPath -ExpectedText "[OK] Listener started." -TimeoutSeconds 60
        if (-not $started) {
            throw "OpenCIFS.TestServer did not start in time for $($DialectMetadata.DialectId)."
        }

        $clientProcess = Start-Process `
            -FilePath "dotnet" `
            -ArgumentList $clientArguments `
            -WorkingDirectory $repositoryRoot `
            -RedirectStandardInput $clientInputPath `
            -RedirectStandardOutput $clientOutputPath `
            -RedirectStandardError $clientErrorPath `
            -WindowStyle Hidden `
            -PassThru `
            -Wait

        $clientExitCode = [int]$clientProcess.ExitCode
        if ($clientExitCode -ne 0) {
            throw "OpenCIFS.TestClient exited with code $clientExitCode for $($DialectMetadata.DialectId)."
        }

        $serverProcess.WaitForExit()

        $serverExitCode = [int]$serverProcess.ExitCode
        if ($serverExitCode -ne 0) {
            throw "OpenCIFS.TestServer exited with code $serverExitCode for $($DialectMetadata.DialectId)."
        }

        Assert-OutputContains -Path $serverOutputPath -ExpectedText "[OK] Listener started."
        Assert-OutputContains -Path $serverOutputPath -ExpectedText "[AUTH]"
        Assert-OutputContains -Path $serverOutputPath -ExpectedText "[TREE]"
        Assert-OutputContains -Path $serverOutputPath -ExpectedText "[CREATE]"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Connected and authenticated."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText ("Negotiated Dialect: " + $DialectMetadata.Dialect)
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Share listing for 127.0.0.1:"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "public [disk]"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "IPC$ [ipc special]"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Share information for ${shareName}:"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Pipe response from ${echoPipeName}:"
        Assert-OutputContains -Path $clientOutputPath -ExpectedText $expectedPipeText
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Opened share '$shareName'."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Created directory /docs."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText $expectedText
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Deleted directory /docs."

        if (-not (Test-Path $downloadPath)) {
            throw "The managed interop run did not produce the downloaded file artifact for $($DialectMetadata.DialectId)."
        }

        $downloadedText = [string](Get-Content -Path $downloadPath -Raw)
        if ($downloadedText -ne $expectedText) {
            throw "The downloaded file text did not match the expected payload for $($DialectMetadata.DialectId)."
        }

        return [pscustomobject]@{
            dialect = $DialectMetadata.Dialect
            dialect_id = $DialectMetadata.DialectId
            label = $DialectMetadata.Label
            require_signing = $true
            require_encryption = [bool]$DialectMetadata.RequireEncryption
            port = $port
            share_name = $shareName
            pipe_name = $echoPipeName
            operations = @(
                "negotiate",
                "session_setup",
                "share_browse",
                "share_info",
                "pipe_transceive",
                "tree_connect",
                "directory_create",
                "file_write",
                "directory_enumerate",
                "metadata_query",
                "file_read",
                "file_rename",
                "file_download",
                "file_delete",
                "directory_delete",
                "tree_disconnect",
                "session_disconnect"
            )
            final_state = [pscustomobject]@{
                failure = $null
            }
            server_output_path = $serverOutputPath
            server_error_path = $serverErrorPath
            client_output_path = $clientOutputPath
            client_error_path = $clientErrorPath
            download_path = $downloadPath
        }
    }
    catch {
        return [pscustomobject]@{
            dialect = $DialectMetadata.Dialect
            dialect_id = $DialectMetadata.DialectId
            label = $DialectMetadata.Label
            require_signing = $true
            require_encryption = [bool]$DialectMetadata.RequireEncryption
            port = $port
            operations = @()
            final_state = [pscustomobject]@{
                failure = $_.Exception.Message
            }
            server_output_path = $serverOutputPath
            server_error_path = $serverErrorPath
            client_output_path = $clientOutputPath
            client_error_path = $clientErrorPath
            download_path = $downloadPath
        }
    }
    finally {
        if ($null -ne $clientProcess -and -not $clientProcess.HasExited) {
            try {
                $clientProcess.Kill()
            }
            catch {
            }
        }

        if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
            try {
                $serverProcess.Kill()
            }
            catch {
            }
        }
    }
}

$runs = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $metadata = Get-DialectMetadata -Dialect $dialect
    $run = Invoke-ManagedInteropRun -DialectMetadata $metadata
    $runs.Add($run)

    if (-not [string]::IsNullOrWhiteSpace([string]$run.final_state.failure)) {
        [pscustomobject]@{
            configuration = $Configuration
            framework = $Framework
            peer_topology = "OpenCIFS.TestClient -> OpenCIFS.TestServer over loopback direct TCP as separate processes"
            runs = $runs
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8
        throw "Managed interop failed for $($metadata.DialectId): $($run.final_state.failure)"
    }
}

[pscustomobject]@{
    configuration = $Configuration
    framework = $Framework
    peer_topology = "OpenCIFS.TestClient -> OpenCIFS.TestServer over loopback direct TCP as separate processes"
    runs = $runs
} | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8

Write-Output "Managed OpenCIFS interop completed."
Write-Output "  $resultPath"

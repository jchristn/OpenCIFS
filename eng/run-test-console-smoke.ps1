param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\test-console-smoke"
$serverInputPath = Join-Path $artifactRoot "server-input.txt"
$clientInputPath = Join-Path $artifactRoot "client-input.txt"
$serverOutputPath = Join-Path $artifactRoot "server-output.txt"
$serverErrorPath = Join-Path $artifactRoot "server-error.txt"
$clientOutputPath = Join-Path $artifactRoot "client-output.txt"
$clientErrorPath = Join-Path $artifactRoot "client-error.txt"
$downloadPath = Join-Path $artifactRoot "download.txt"
$resultPath = Join-Path $artifactRoot "test-console-smoke.json"
$shareName = "public"
$userName = "tester"
$password = "Password123!"
$echoPipeName = "opencifs.echo"
$expectedText = "Hello from OpenCIFS.TestClient"
$expectedPipeText = "Hello from OpenCIFS.TestClient pipe"

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

$port = Get-FreeTcpPort

@(
    "server 127.0.0.1",
    "bind 127.0.0.1",
    "port $port",
    "share $shareName",
    "user $userName",
    "password $password",
    "start",
    "wait 8",
    "q"
) | Out-File -FilePath $serverInputPath -Encoding ascii

@(
    "server 127.0.0.1",
    "port $port",
    "user $userName",
    "password $password",
    "connect",
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
        -PassThru

    $started = Wait-ForConsoleOutput -Process $serverProcess -Path $serverOutputPath -ExpectedText "[OK] Listener started."
    if (-not $started) {
        if (Test-Path $serverOutputPath) {
            Get-Content -Path $serverOutputPath
        }

        if (Test-Path $serverErrorPath) {
            Get-Content -Path $serverErrorPath
        }

        throw "OpenCIFS.TestServer did not start in time."
    }

    $clientProcess = Start-Process `
        -FilePath "dotnet" `
        -ArgumentList $clientArguments `
        -WorkingDirectory $repositoryRoot `
        -RedirectStandardInput $clientInputPath `
        -RedirectStandardOutput $clientOutputPath `
        -RedirectStandardError $clientErrorPath `
        -PassThru `
        -Wait

    $clientExitCode = [int]$clientProcess.ExitCode
    if ($clientExitCode -ne 0) {
        if (Test-Path $clientOutputPath) {
            Get-Content -Path $clientOutputPath
        }

        if (Test-Path $clientErrorPath) {
            Get-Content -Path $clientErrorPath
        }

        throw "OpenCIFS.TestClient exited with code $clientExitCode."
    }

    $serverProcess.WaitForExit()

    $serverExitCode = [int]$serverProcess.ExitCode
    if ($serverExitCode -ne 0) {
        if (Test-Path $serverOutputPath) {
            Get-Content -Path $serverOutputPath
        }

        if (Test-Path $serverErrorPath) {
            Get-Content -Path $serverErrorPath
        }

        throw "OpenCIFS.TestServer exited with code $serverExitCode."
    }

    Assert-OutputContains -Path $serverOutputPath -ExpectedText "[OK] Listener started."
    Assert-OutputContains -Path $serverOutputPath -ExpectedText "[AUTH]"
    Assert-OutputContains -Path $serverOutputPath -ExpectedText "[TREE]"
    Assert-OutputContains -Path $serverOutputPath -ExpectedText "[CREATE]"
    Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Connected and authenticated."
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
        throw "The tester-console smoke did not produce the downloaded file artifact."
    }

    $downloadedText = [string](Get-Content -Path $downloadPath -Raw)
    if ($downloadedText -ne $expectedText) {
        throw "The downloaded file text did not match the expected round-trip payload."
    }

    $serverOutputText = Get-Content -Path $serverOutputPath -Raw
    $serverRootPath = [string]::Empty
    $serverRootMatch = [regex]::Match($serverOutputText, "Temporary backing store: (?<path>.+)")
    if ($serverRootMatch.Success) {
        $serverRootPath = $serverRootMatch.Groups["path"].Value.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($serverRootPath)) {
        Assert-OutputContains -Path $clientOutputPath -ExpectedText $serverRootPath
    }

    [pscustomobject]@{
        Configuration = $Configuration
        Framework = $Framework
        Port = $port
        ShareName = $shareName
        PipeName = $echoPipeName
        UserName = $userName
        ExpectedText = $expectedText
        ExpectedPipeText = $expectedPipeText
        DownloadedText = $downloadedText
        ServerRootPath = $serverRootPath
        ServerOutputPath = $serverOutputPath
        ServerErrorPath = $serverErrorPath
        ClientOutputPath = $clientOutputPath
        ClientErrorPath = $clientErrorPath
        DownloadPath = $downloadPath
        Succeeded = $true
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $resultPath -Encoding UTF8

    Write-Output "Tester-console smoke completed."
    Write-Output "  $resultPath"
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

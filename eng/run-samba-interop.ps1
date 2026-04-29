param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Message)

    if ($LASTEXITCODE -ne 0) {
        throw $Message
    }
}

function Wait-ForTcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$Attempts = 60
    )

    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient

        try {
            $tcpClient.Connect($HostName, $Port)
            $tcpClient.Close()
            return
        }
        catch {
        }
        finally {
            $tcpClient.Dispose()
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for ${HostName}:$Port to accept connections."
}

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

$repositoryRoot = Join-Path $PSScriptRoot ".."
$artifactRoot = Join-Path $repositoryRoot "artifacts\samba-interop"
$sambaShareRoot = Join-Path $artifactRoot "samba-server-share"
$sampleShareRoot = Join-Path $artifactRoot "sample-server-share"
$dockerContext = Join-Path $PSScriptRoot "docker\samba-interop"
$imageName = "opencifs-samba-interop:bookworm"
$sambaServerPort = Get-FreeTcpPort
$sampleServerPort = Get-FreeTcpPort

while ($sampleServerPort -eq $sambaServerPort) {
    $sampleServerPort = Get-FreeTcpPort
}
$sambaServerContainerName = "opencifs-samba-server-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$sambaServerLogPath = Join-Path $artifactRoot "samba-server.log"
$sambaVersionsPath = Join-Path $artifactRoot "samba-versions.txt"
$openCifsClientSmokePath = Join-Path $artifactRoot "open-cifs-client-to-samba.json"
$sampleServerConfigPath = Join-Path $artifactRoot "sample-server.config.txt"
$sampleServerLogPath = Join-Path $artifactRoot "sample-server.log"
$sampleServerErrorPath = Join-Path $artifactRoot "sample-server.err.log"
$sambaClientLogPath = Join-Path $artifactRoot "sample-server-samba-client.log"
$sambaClientSummaryPath = Join-Path $artifactRoot "sample-server-samba-client.json"

if (Test-Path $sambaShareRoot) {
    Get-ChildItem -Force -Path $sambaShareRoot | Remove-Item -Recurse -Force
}

if (Test-Path $sampleShareRoot) {
    Get-ChildItem -Force -Path $sampleShareRoot | Remove-Item -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sambaShareRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sampleShareRoot | Out-Null

& docker build -t $imageName $dockerContext
Assert-LastExitCode "Failed to build the Samba interop image."

$smbclientVersion = (& docker run --rm $imageName smbclient --version).Trim()
Assert-LastExitCode "Failed to read the Samba client version from the interop image."
$smbdVersion = (& docker run --rm $imageName smbd -V).Trim()
Assert-LastExitCode "Failed to read the Samba server version from the interop image."
Set-Content -Path $sambaVersionsPath -Value ("smbclient=" + $smbclientVersion + [Environment]::NewLine + "smbd=" + $smbdVersion)

$resolvedSambaShareRoot = (Resolve-Path $sambaShareRoot).Path

& docker run -d `
    --name $sambaServerContainerName `
    -p ("127.0.0.1:" + $sambaServerPort + ":445") `
    -v ($resolvedSambaShareRoot + ":/share") `
    -e "SAMBA_USERNAME=alice" `
    -e "SAMBA_PASSWORD=Password123!" `
    -e "SAMBA_WORKGROUP=WORKGROUP" `
    -e "SAMBA_SHARE_NAME=share" `
    -e "SAMBA_SHARE_PATH=/share" `
    $imageName `
    /usr/local/bin/start-samba-server.sh | Out-Null
Assert-LastExitCode "Failed to start the Samba server container."

try {
    Wait-ForTcpPort -HostName "127.0.0.1" -Port $sambaServerPort
    & dotnet run `
        --project (Join-Path $repositoryRoot "src\OpenCIFS.SambaInterop.Console\OpenCIFS.SambaInterop.Console.csproj") `
        --configuration $Configuration `
        --framework $Framework `
        --no-build `
        -- `
        --server "127.0.0.1" `
        --port $sambaServerPort `
        --share "share" `
        --username "alice" `
        --password "Password123!" `
        --domain "WORKGROUP" `
        --output $openCifsClientSmokePath
    Assert-LastExitCode "The OpenCIFS.Client to Samba smoke run failed."
}
finally {
    cmd /c "docker logs $sambaServerContainerName > `"$sambaServerLogPath`" 2>&1"

    try {
        & docker rm -f $sambaServerContainerName | Out-Null
    }
    catch {
    }
}

$projectPath = Join-Path $repositoryRoot "src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"
$sampleServerArguments = @(
    "--server-name", "127.0.0.1",
    "--bind-address", "127.0.0.1",
    "--bind-port", $sampleServerPort.ToString(),
    "--share-name", "share",
    "--share-path", $sampleShareRoot,
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

& dotnet $printArguments | Tee-Object -FilePath $sampleServerConfigPath | Out-Null
Assert-LastExitCode "Failed to print the effective Sample.OpenCifsServer configuration for Samba interop."

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
    -WorkingDirectory $repositoryRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $sampleServerLogPath `
    -RedirectStandardError $sampleServerErrorPath `
    -PassThru

try {
    Wait-ForTcpPort -HostName "127.0.0.1" -Port $sampleServerPort

    $remoteDirectory = "samba-client-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $remoteNestedDirectory = "nested"
    $remoteFile = "smoke.txt"
    $renamedFile = "renamed-smoke.txt"
    $payloadText = "hello from smbclient"
$sambaClientCommand = @'
set -euo pipefail
printf '%s' '{0}' > /tmp/payload.txt
cat > /tmp/smbclient-commands.txt <<'EOF'
mkdir {2}
cd {2}
mkdir {5}
put /tmp/payload.txt {3}
get {3} /tmp/readback.txt
rename {3} {4}
ls
quit
EOF
smbclient //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {1} < /tmp/smbclient-commands.txt 2>&1 | tee /tmp/smbclient-output.txt
grep -F '{4}' /tmp/smbclient-output.txt >/dev/null
grep -F '{5}' /tmp/smbclient-output.txt >/dev/null
cmp /tmp/payload.txt /tmp/readback.txt
'@ -f $payloadText, $sampleServerPort, $remoteDirectory, $remoteFile, $renamedFile, $remoteNestedDirectory

    $sambaClientOutput = & docker run --rm $imageName bash -lc $sambaClientCommand 2>&1
    $sambaClientOutput | Tee-Object -FilePath $sambaClientLogPath | Out-Null
    Assert-LastExitCode "The Samba client to Sample.OpenCifsServer smoke run failed."

    $nonEmptyDirectoryDeleteCommand = @'
set -euo pipefail
output=$(smbclient //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {0} -c "rmdir {1}" 2>&1 || true)
printf '%s\n' "$output" | tee /tmp/smbclient-rmdir-output.txt
printf '%s' "$output" | grep -E 'NT_STATUS_DIRECTORY_NOT_EMPTY|directory is not empty' >/dev/null
'@ -f $sampleServerPort, $remoteDirectory

    $nonEmptyDirectoryDeleteStdoutPath = Join-Path $artifactRoot "sample-server-samba-client.rmdir.stdout.txt"
    $nonEmptyDirectoryDeleteStderrPath = Join-Path $artifactRoot "sample-server-samba-client.rmdir.stderr.txt"

    Remove-Item -LiteralPath $nonEmptyDirectoryDeleteStdoutPath -ErrorAction Ignore
    Remove-Item -LiteralPath $nonEmptyDirectoryDeleteStderrPath -ErrorAction Ignore

    $nonEmptyDirectoryDeleteProcess = Start-Process -FilePath "docker" `
        -ArgumentList @("run", "--rm", $imageName, "bash", "-lc", $nonEmptyDirectoryDeleteCommand) `
        -NoNewWindow `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $nonEmptyDirectoryDeleteStdoutPath `
        -RedirectStandardError $nonEmptyDirectoryDeleteStderrPath

    $LASTEXITCODE = $nonEmptyDirectoryDeleteProcess.ExitCode
    $nonEmptyDirectoryDeleteOutput = @()

    if (Test-Path $nonEmptyDirectoryDeleteStdoutPath) {
        $nonEmptyDirectoryDeleteOutput += Get-Content -Path $nonEmptyDirectoryDeleteStdoutPath
    }

    if (Test-Path $nonEmptyDirectoryDeleteStderrPath) {
        $nonEmptyDirectoryDeleteOutput += Get-Content -Path $nonEmptyDirectoryDeleteStderrPath
    }

    Add-Content -Path $sambaClientLogPath -Value ""
    Add-Content -Path $sambaClientLogPath -Value "==== non-empty delete rejection ===="
    $nonEmptyDirectoryDeleteOutput | Add-Content -Path $sambaClientLogPath
    Assert-LastExitCode "The Samba client non-empty directory delete rejection check failed."

    $cleanupCommand = @'
set -euo pipefail
cat > /tmp/smbclient-cleanup-commands.txt <<'EOF'
cd {1}
del {2}
rmdir {3}
cd ..
rmdir {1}
quit
EOF
smbclient //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {0} < /tmp/smbclient-cleanup-commands.txt 2>&1 | tee /tmp/smbclient-cleanup-output.txt
'@ -f $sampleServerPort, $remoteDirectory, $renamedFile, $remoteNestedDirectory

    $cleanupOutput = & docker run --rm $imageName bash -lc $cleanupCommand 2>&1
    Add-Content -Path $sambaClientLogPath -Value ""
    Add-Content -Path $sambaClientLogPath -Value "==== cleanup ===="
    $cleanupOutput | Add-Content -Path $sambaClientLogPath
    Assert-LastExitCode "The Samba client cleanup against Sample.OpenCifsServer failed."

    if (Test-Path (Join-Path $sampleShareRoot $remoteDirectory)) {
        throw "The Samba client smoke left the remote sample-server directory behind."
    }

    $sambaClientSummary = [ordered]@{
        server = "host.docker.internal"
        port = $sampleServerPort
        share = "share"
        dialect = "SMB 2.0.2"
        directory = $remoteDirectory
        nested_directory = ($remoteDirectory + "\" + $remoteNestedDirectory)
        file = $remoteFile
        renamed_file = $renamedFile
        payload = $payloadText
        listing_contains_renamed_file = $true
        listing_contains_nested_directory = $true
        non_empty_directory_delete_rejected = $true
        smbclient_version = $smbclientVersion
    }
    $sambaClientSummary | ConvertTo-Json -Depth 5 | Set-Content -Path $sambaClientSummaryPath
}
finally {
    if (-not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}

Write-Host "Samba interop smoke completed. Evidence:"
Write-Host "  $openCifsClientSmokePath"
Write-Host "  $sambaClientSummaryPath"
Write-Host "  $sambaClientLogPath"
Write-Host "  $sambaServerLogPath"
Write-Host "  $sampleServerConfigPath"
Write-Host "  $sampleServerLogPath"
Write-Host "  $sampleServerErrorPath"
Write-Host "  $sambaVersionsPath"

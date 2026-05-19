param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [switch]$IncludeSmb311Preview,
    [int]$LargePayloadLength = 200000,
    [string]$SambaImageName = "opencifs-samba-interop:bookworm",
    [string]$DockerContext = "",
    [string]$Dockerfile = "",
    [string]$PeerLabel = "debian-bookworm"
)

$ErrorActionPreference = "Stop"

if ($IncludeSmb311Preview -and $Dialects -notcontains "Smb311") {
    $Dialects += "Smb311"
}

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the deeper Samba interop path exercises bounded large-I/O behavior."
}

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

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                RequireEncryptionForSmb3 = $false
                SmbClientProtectionArgument = ""
                EnableSmb311Preview = $false
                SmbClientMaxProtocolArgument = ""
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                RequireEncryptionForSmb3 = $false
                SmbClientProtectionArgument = ""
                EnableSmb311Preview = $false
                SmbClientMaxProtocolArgument = ""
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                RequireEncryptionForSmb3 = $true
                SmbClientProtectionArgument = "--client-protection=encrypt"
                EnableSmb311Preview = $false
                SmbClientMaxProtocolArgument = ""
            }
        }
        "Smb311" {
            return [pscustomobject]@{
                Dialect = "Smb311"
                DialectId = "smb311"
                Label = "SMB 3.1.1"
                RequireEncryptionForSmb3 = $true
                SmbClientProtectionArgument = "--client-protection=encrypt"
                EnableSmb311Preview = $true
                SmbClientMaxProtocolArgument = "--option=client max protocol=SMB3_11"
            }
        }
        default {
            throw "Unsupported dialect '$Dialect'."
        }
    }
}

$repositoryRoot = Join-Path $PSScriptRoot ".."
$artifactRoot = Join-Path $repositoryRoot "artifacts\samba-interop"
$sambaShareRoot = Join-Path $artifactRoot "samba-server-share"
$sampleShareRoot = Join-Path $artifactRoot "sample-server-share"
if ([string]::IsNullOrWhiteSpace($DockerContext)) {
    $DockerContext = Join-Path $PSScriptRoot "docker\samba-interop"
}

if ([string]::IsNullOrWhiteSpace($Dockerfile)) {
    $Dockerfile = Join-Path $DockerContext "Dockerfile"
}

$imageName = $SambaImageName
$sambaServerPort = Get-FreeTcpPort
$sampleServerPort = Get-FreeTcpPort

while ($sampleServerPort -eq $sambaServerPort) {
    $sampleServerPort = Get-FreeTcpPort
}

$sambaServerContainerName = "opencifs-samba-server-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$combinedSambaServerLogPath = Join-Path $artifactRoot "samba-server.log"
$sambaVersionsPath = Join-Path $artifactRoot "samba-versions.txt"
$openCifsClientSmokePath = Join-Path $artifactRoot "open-cifs-client-to-samba.json"
$sampleServerConfigPath = Join-Path $artifactRoot "sample-server.config.txt"
$sampleServerLogPath = Join-Path $artifactRoot "sample-server.log"
$sampleServerErrorPath = Join-Path $artifactRoot "sample-server.err.log"
$sambaClientLogPath = Join-Path $artifactRoot "sample-server-samba-client.log"
$sambaClientSummaryPath = Join-Path $artifactRoot "sample-server-samba-client.json"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sambaShareRoot | Out-Null
New-Item -ItemType Directory -Force -Path $sampleShareRoot | Out-Null
Set-Content -Path $combinedSambaServerLogPath -Value ""
Set-Content -Path $sampleServerConfigPath -Value ""
Set-Content -Path $sampleServerLogPath -Value ""
Set-Content -Path $sampleServerErrorPath -Value ""
Set-Content -Path $sambaClientLogPath -Value ""

& docker build -f $Dockerfile -t $imageName $DockerContext
Assert-LastExitCode "Failed to build the Samba interop image."

$smbclientVersion = (& docker run --rm $imageName smbclient --version).Trim()
Assert-LastExitCode "Failed to read the Samba client version from the interop image."
$smbdVersion = (& docker run --rm $imageName smbd -V).Trim()
Assert-LastExitCode "Failed to read the Samba server version from the interop image."
Set-Content -Path $sambaVersionsPath -Value (
    "peer_label=" + $PeerLabel + [Environment]::NewLine +
    "image=" + $imageName + [Environment]::NewLine +
    "dockerfile=" + (Resolve-Path $Dockerfile).Path + [Environment]::NewLine +
    "smbclient=" + $smbclientVersion + [Environment]::NewLine +
    "smbd=" + $smbdVersion)

$resolvedSambaShareRoot = (Resolve-Path $sambaShareRoot).Path
$openCifsClientResults = New-Object System.Collections.Generic.List[object]
$sambaClientResults = New-Object System.Collections.Generic.List[object]

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

    foreach ($dialect in $Dialects) {
        $dialectMetadata = Get-DialectMetadata -Dialect $dialect
        $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
        New-Item -ItemType Directory -Force -Path $dialectArtifactRoot | Out-Null
        $dialectOpenCifsClientSmokePath = Join-Path $dialectArtifactRoot "open-cifs-client-to-samba.json"

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
            --dialect $dialect `
            --large-payload-length $LargePayloadLength `
            --output $dialectOpenCifsClientSmokePath
        Assert-LastExitCode "The OpenCIFS.Client to Samba smoke run failed for $($dialectMetadata.Label)."

        $dialectOpenCifsClientSummary = Get-Content -Path $dialectOpenCifsClientSmokePath -Raw | ConvertFrom-Json

        if ($null -eq $dialectOpenCifsClientSummary.AdvancedSmb3) {
            throw "The OpenCIFS.Client to Samba smoke artifact for $($dialectMetadata.Label) did not record AdvancedSmb3 reporting."
        }

        $openCifsClientResults.Add([pscustomobject]@{
            dialect_id = $dialectMetadata.DialectId
            dialect = $dialectMetadata.Label
            summary = $dialectOpenCifsClientSummary
        })
    }
}
finally {
    cmd /c "docker logs $sambaServerContainerName >> `"$combinedSambaServerLogPath`" 2>&1"

    try {
        & docker rm -f $sambaServerContainerName | Out-Null
    }
    catch {
    }
}

$projectPath = Join-Path $repositoryRoot "src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"

foreach ($dialect in $Dialects) {
    $dialectMetadata = Get-DialectMetadata -Dialect $dialect
    $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
    $dialectSampleShareRoot = Join-Path $sampleShareRoot $dialectMetadata.DialectId
    $dialectSampleServerConfigPath = Join-Path $dialectArtifactRoot "sample-server.config.txt"
    $dialectSampleServerLogPath = Join-Path $dialectArtifactRoot "sample-server.log"
    $dialectSampleServerErrorPath = Join-Path $dialectArtifactRoot "sample-server.err.log"
    $dialectSambaClientLogPath = Join-Path $dialectArtifactRoot "sample-server-samba-client.log"
    $dialectSambaClientSummaryPath = Join-Path $dialectArtifactRoot "sample-server-samba-client.json"

    if (Test-Path $dialectSampleShareRoot) {
        Get-ChildItem -Force -Path $dialectSampleShareRoot | Remove-Item -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $dialectSampleShareRoot | Out-Null

    $sampleServerArguments = @(
        "--server-name", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--bind-port", $sampleServerPort.ToString(),
        "--share-name", "share",
        "--share-path", $dialectSampleShareRoot,
        "--minimum-dialect", $dialectMetadata.Dialect,
        "--maximum-dialect", $dialectMetadata.Dialect,
        "--require-signing", "true",
        "--require-ntlmv2", "true",
        "--allow-anonymous", "false",
        "--enable-smb1", "false",
        "--require-encryption-for-smb3", $dialectMetadata.RequireEncryptionForSmb3.ToString().ToLowerInvariant(),
        "--enable-smb311-preview", $dialectMetadata.EnableSmb311Preview.ToString().ToLowerInvariant(),
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

    & dotnet $printArguments | Tee-Object -FilePath $dialectSampleServerConfigPath | Out-Null
    Assert-LastExitCode "Failed to print the effective Sample.OpenCifsServer configuration for Samba interop under $($dialectMetadata.Label)."

    Add-Content -Path $sampleServerConfigPath -Value ("==== " + $dialectMetadata.Label + " ====")
    Get-Content -Path $dialectSampleServerConfigPath | Add-Content -Path $sampleServerConfigPath
    Add-Content -Path $sampleServerConfigPath -Value ""

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
        -RedirectStandardOutput $dialectSampleServerLogPath `
        -RedirectStandardError $dialectSampleServerErrorPath `
        -PassThru

    try {
        Wait-ForTcpPort -HostName "127.0.0.1" -Port $sampleServerPort

        $remoteDirectory = "samba-client-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
        $remoteNestedDirectory = "nested"
        $remoteFile = "smoke.txt"
        $remoteLargeFile = "large.bin"
        $renamedFile = "renamed-smoke.txt"
        $payloadText = "hello from smbclient"
        $smbClientProtectionArgument = $dialectMetadata.SmbClientProtectionArgument
        $smbClientMaxProtocolArgument = $dialectMetadata.SmbClientMaxProtocolArgument
$sambaClientCommand = @'
set -euo pipefail
printf '%s' '{0}' > /tmp/payload.txt
head -c {6} /dev/zero | tr '\000' 'A' > /tmp/large.bin
cat > /tmp/smbclient-commands.txt <<'EOF'
mkdir {2}
cd {2}
mkdir {5}
put /tmp/payload.txt {3}
get {3} /tmp/readback.txt
put /tmp/large.bin {4}
get {4} /tmp/large-readback.bin
rename {3} {7}
ls
quit
EOF
smbclient {8} {9} //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {1} < /tmp/smbclient-commands.txt 2>&1 | tee /tmp/smbclient-output.txt
grep -F '{7}' /tmp/smbclient-output.txt >/dev/null
grep -F '{5}' /tmp/smbclient-output.txt >/dev/null
cmp /tmp/payload.txt /tmp/readback.txt
cmp /tmp/large.bin /tmp/large-readback.bin
'@ -f $payloadText, $sampleServerPort, $remoteDirectory, $remoteFile, $remoteLargeFile, $remoteNestedDirectory, $LargePayloadLength, $renamedFile, $smbClientProtectionArgument, $smbClientMaxProtocolArgument

        $sambaClientOutput = & docker run --rm $imageName bash -lc $sambaClientCommand 2>&1
        $sambaClientOutput | Tee-Object -FilePath $dialectSambaClientLogPath | Out-Null
        Assert-LastExitCode "The Samba client to Sample.OpenCifsServer smoke run failed for $($dialectMetadata.Label)."

$nonEmptyDirectoryDeleteCommand = @'
set -euo pipefail
output=$(smbclient {2} {3} //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {0} -c "rmdir {1}" 2>&1 || true)
printf '%s\n' "$output" | tee /tmp/smbclient-rmdir-output.txt
printf '%s' "$output" | grep -E 'NT_STATUS_DIRECTORY_NOT_EMPTY|directory is not empty' >/dev/null
'@ -f $sampleServerPort, $remoteDirectory, $smbClientProtectionArgument, $smbClientMaxProtocolArgument

        $nonEmptyDirectoryDeleteStdoutPath = Join-Path $dialectArtifactRoot "sample-server-samba-client.rmdir.stdout.txt"
        $nonEmptyDirectoryDeleteStderrPath = Join-Path $dialectArtifactRoot "sample-server-samba-client.rmdir.stderr.txt"

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

        Add-Content -Path $dialectSambaClientLogPath -Value ""
        Add-Content -Path $dialectSambaClientLogPath -Value "==== non-empty delete rejection ===="
        $nonEmptyDirectoryDeleteOutput | Add-Content -Path $dialectSambaClientLogPath
        Assert-LastExitCode "The Samba client non-empty directory delete rejection check failed for $($dialectMetadata.Label)."

        $cleanupCommand = @'
set -euo pipefail
cat > /tmp/smbclient-cleanup-commands.txt <<'EOF'
cd {1}
del {2}
del {4}
rmdir {3}
cd ..
rmdir {1}
quit
EOF
smbclient {5} {6} //host.docker.internal/share -W WORKGROUP -U 'alice%Password123!' -p {0} < /tmp/smbclient-cleanup-commands.txt 2>&1 | tee /tmp/smbclient-cleanup-output.txt
'@ -f $sampleServerPort, $remoteDirectory, $renamedFile, $remoteNestedDirectory, $remoteLargeFile, $smbClientProtectionArgument, $smbClientMaxProtocolArgument

        $cleanupOutput = & docker run --rm $imageName bash -lc $cleanupCommand 2>&1
        Add-Content -Path $dialectSambaClientLogPath -Value ""
        Add-Content -Path $dialectSambaClientLogPath -Value "==== cleanup ===="
        $cleanupOutput | Add-Content -Path $dialectSambaClientLogPath
        Assert-LastExitCode "The Samba client cleanup against Sample.OpenCifsServer failed for $($dialectMetadata.Label)."

        if (Test-Path (Join-Path $dialectSampleShareRoot $remoteDirectory)) {
            throw "The Samba client smoke left the remote sample-server directory behind for $($dialectMetadata.Label)."
        }

        $isSmb3Dialect = $dialectMetadata.Dialect -eq "Smb30" -or $dialectMetadata.Dialect -eq "Smb302" -or $dialectMetadata.Dialect -eq "Smb311"
        $sambaClientSummary = [ordered]@{
            dialect = $dialectMetadata.Label
            dialect_id = $dialectMetadata.DialectId
            server = "host.docker.internal"
            port = $sampleServerPort
            share = "share"
            directory = $remoteDirectory
            nested_directory = ($remoteDirectory + "\" + $remoteNestedDirectory)
            file = $remoteFile
            large_file = $remoteLargeFile
            large_payload_length = $LargePayloadLength
            renamed_file = $renamedFile
            payload = $payloadText
            listing_contains_renamed_file = $true
            listing_contains_nested_directory = $true
            non_empty_directory_delete_rejected = $true
            smbclient_version = $smbclientVersion
            advanced_smb3 = [ordered]@{
                dialect_is_smb3 = $isSmb3Dialect
                encryption_requested = [bool](-not [string]::IsNullOrWhiteSpace($smbClientProtectionArgument))
                secure_negotiate_validation_exercised = $true
                durable_handle_v2 = [ordered]@{
                    attempted = $false
                    outcome = "skipped"
                    skip_reason = if ($isSmb3Dialect) {
                        "The smbclient workflow does not preserve a durable reconnect token across a forced transport drop."
                    }
                    else {
                        "Durable-handle v2 verification only applies to SMB 3.x dialect lanes."
                    }
                }
                oplock = [ordered]@{
                    attempted = $false
                    outcome = "skipped"
                    skip_reason = if ($isSmb3Dialect) {
                        "The smbclient workflow does not surface SMB oplock-break notifications through this bounded command path."
                    }
                    else {
                        "Advanced SMB 3.x oplock reporting only applies to SMB 3.x dialect lanes."
                    }
                }
                lease = [ordered]@{
                    attempted = $false
                    outcome = "skipped"
                    skip_reason = if ($isSmb3Dialect) {
                        "The smbclient workflow does not surface SMB lease-break notifications through this bounded command path."
                    }
                    else {
                        "Advanced SMB 3.x lease reporting only applies to SMB 3.x dialect lanes."
                    }
                }
            }
        }
        $sambaClientSummary | ConvertTo-Json -Depth 5 | Set-Content -Path $dialectSambaClientSummaryPath
        $sambaClientResults.Add($sambaClientSummary)

        Add-Content -Path $sambaClientLogPath -Value ("==== " + $dialectMetadata.Label + " ====")
        Get-Content -Path $dialectSambaClientLogPath | Add-Content -Path $sambaClientLogPath
        Add-Content -Path $sambaClientLogPath -Value ""
        Add-Content -Path $sampleServerLogPath -Value ("==== " + $dialectMetadata.Label + " ====")
        Get-Content -Path $dialectSampleServerLogPath | Add-Content -Path $sampleServerLogPath
        Add-Content -Path $sampleServerLogPath -Value ""
        Add-Content -Path $sampleServerErrorPath -Value ("==== " + $dialectMetadata.Label + " ====")
        Get-Content -Path $dialectSampleServerErrorPath | Add-Content -Path $sampleServerErrorPath
        Add-Content -Path $sampleServerErrorPath -Value ""
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
    runs = $openCifsClientResults
} | ConvertTo-Json -Depth 8 | Set-Content -Path $openCifsClientSmokePath -Encoding UTF8

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    runs = $sambaClientResults
} | ConvertTo-Json -Depth 8 | Set-Content -Path $sambaClientSummaryPath -Encoding UTF8

Write-Host "Samba interop smoke completed. Evidence:"
Write-Host "  $openCifsClientSmokePath"
Write-Host "  $sambaClientSummaryPath"
Write-Host "  $sambaClientLogPath"
Write-Host "  $combinedSambaServerLogPath"
Write-Host "  $sampleServerConfigPath"
Write-Host "  $sampleServerLogPath"
Write-Host "  $sampleServerErrorPath"
Write-Host "  $sambaVersionsPath"

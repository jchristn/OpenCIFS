param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [int]$LargePayloadLength = 200000,
    [string]$ImageName = ""
)

$ErrorActionPreference = "Stop"

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the Linux CIFS path exercises bounded large-I/O behavior."
}

if ([string]::IsNullOrWhiteSpace($ImageName)) {
    $ImageName = [Environment]::GetEnvironmentVariable("OPENCIFS_LINUX_CIFS_IMAGE_NAME")
}

if ([string]::IsNullOrWhiteSpace($ImageName)) {
    $ImageName = "opencifs-linux-cifs-interop:bookworm"
}

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Message)

    if ($LASTEXITCODE -ne 0) {
        throw $Message
    }
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

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                MountVersion = "2.0"
                RequireEncryptionForSmb3 = $false
                MountSecurityOptions = "sec=ntlmssp"
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                MountVersion = "2.1"
                RequireEncryptionForSmb3 = $false
                MountSecurityOptions = "sec=ntlmssp"
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                MountVersion = "3.02"
                RequireEncryptionForSmb3 = $true
                MountSecurityOptions = "sec=ntlmssp,seal"
            }
        }
        default {
            throw "Unsupported Linux CIFS interop dialect '$Dialect'."
        }
    }
}

function Test-IsExpectedLegacyDialectMountBlock {
    param(
        [Parameter(Mandatory = $true)][string]$CombinedOutput
    )

    return $CombinedOutput.IndexOf(
        "vers=2.0 mount not permitted when legacy dialects disabled",
        [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Test-IsWsl2LegacyDialectBlockedHost {
    param(
        [Parameter(Mandatory = $true)][string]$LinuxKernelRelease
    )

    return $LinuxKernelRelease.IndexOf(
        "microsoft-standard-WSL2",
        [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\linux-cifs-interop"
$dockerContext = Join-Path $PSScriptRoot "docker\linux-cifs-interop"
$resultPath = Join-Path $artifactRoot "linux-cifs-interop.json"
$environmentPath = Join-Path $artifactRoot "linux-cifs-environment.json"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

& docker build -t $ImageName $dockerContext
Assert-LastExitCode "Failed to build the Linux CIFS interop image."

$mountCifsVersion = (& docker run --rm --privileged $ImageName mount.cifs -V 2>&1) -join [Environment]::NewLine
Assert-LastExitCode "Failed to read the mount.cifs version from the interop image."
$linuxKernelRelease = (& docker run --rm --privileged $ImageName uname -r 2>&1) -join [Environment]::NewLine
Assert-LastExitCode "Failed to read the Linux kernel release from the interop image."

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    client_machine = $env:COMPUTERNAME
    os_version = [System.Environment]::OSVersion.VersionString
    image = $ImageName
    docker_context = (Resolve-Path $dockerContext).Path
    mount_cifs_version = $mountCifsVersion
    linux_kernel_release = $linuxKernelRelease
} | ConvertTo-Json -Depth 4 | Set-Content -Path $environmentPath -Encoding UTF8

$projectPath = Join-Path $repositoryRoot "src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"
$runs = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $dialectMetadata = Get-DialectMetadata -Dialect $dialect
    $dialectArtifactRoot = Join-Path $artifactRoot $dialectMetadata.DialectId
    $shareRoot = Join-Path $dialectArtifactRoot "share"
    $serverConfigPath = Join-Path $dialectArtifactRoot "sample-server.config.txt"
    $serverLogPath = Join-Path $dialectArtifactRoot "sample-server.log"
    $serverErrorPath = Join-Path $dialectArtifactRoot "sample-server.err.log"
    $clientScriptPath = Join-Path $dialectArtifactRoot "linux-cifs-client.sh"
    $clientLogPath = Join-Path $dialectArtifactRoot "linux-cifs-client.log"
    $clientErrorPath = Join-Path $dialectArtifactRoot "linux-cifs-client.err.log"
    $clientSummaryPath = Join-Path $dialectArtifactRoot "linux-cifs-client.json"
    $port = Get-FreeTcpPort

    New-Item -ItemType Directory -Path $dialectArtifactRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null

    if (
        $dialectMetadata.DialectId -eq "smb2002" -and
        (Test-IsWsl2LegacyDialectBlockedHost -LinuxKernelRelease $linuxKernelRelease)) {
        $skipReason = "Linux kernel CIFS mount is host-policy-blocked for vers=2.0 on this WSL2/Docker Desktop host before any OpenCIFS traffic reaches the server."
        Set-Content -Path $serverConfigPath -Value $skipReason -Encoding UTF8
        Set-Content -Path $serverLogPath -Value $skipReason -Encoding UTF8
        Set-Content -Path $serverErrorPath -Value "" -Encoding UTF8
        Set-Content -Path $clientScriptPath -Value "# skipped: $skipReason" -Encoding UTF8
        Set-Content -Path $clientLogPath -Value "" -Encoding UTF8
        Set-Content -Path $clientErrorPath -Value ("Kernel: " + $linuxKernelRelease) -Encoding UTF8

        $summary = [ordered]@{
            dialect = $dialectMetadata.Label
            dialect_id = $dialectMetadata.DialectId
            mount_version = $dialectMetadata.MountVersion
            mount_options = "username=alice,password=Password123!,domain=WORKGROUP,port=$port,vers=$($dialectMetadata.MountVersion),$($dialectMetadata.MountSecurityOptions),noserverino"
            server = "host.docker.internal"
            port = $port
            share = "share"
            directory = $null
            payload = $null
            large_payload_length = $LargePayloadLength
            listing_contains_renamed_file = $null
            listing_contains_nested_directory = $null
            non_empty_directory_delete_rejected = $null
            mount_cifs_version = $mountCifsVersion
            final_state = [pscustomobject]@{
                failure = $null
                skipped = $true
                skip_reason = $skipReason
                skip_detail = "Kernel: $linuxKernelRelease"
            }
            client_script_path = $clientScriptPath
            client_log_path = $clientLogPath
            client_error_path = $clientErrorPath
            server_config_path = $serverConfigPath
            server_log_path = $serverLogPath
            server_error_path = $serverErrorPath
        }

        $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $clientSummaryPath -Encoding UTF8
        $runs.Add($summary)
        continue
    }

    $sampleServerArguments = @(
        "--server-name", "127.0.0.1",
        "--bind-address", "127.0.0.1",
        "--bind-port", $port.ToString([System.Globalization.CultureInfo]::InvariantCulture),
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

    & dotnet $printArguments | Tee-Object -FilePath $serverConfigPath | Out-Null
    Assert-LastExitCode "Failed to print the effective Sample.OpenCifsServer configuration for Linux CIFS interop under $($dialectMetadata.Label)."

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
        -RedirectStandardOutput $serverLogPath `
        -RedirectStandardError $serverErrorPath `
        -PassThru

    try {
        Wait-ForTcpPort -HostName "127.0.0.1" -Port $port

        $remoteDirectory = "linux-cifs-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
        $payloadText = "hello from linux kernel cifs"
        $mountOptions = "username=alice,password=Password123!,domain=WORKGROUP,port=$port,vers=$($dialectMetadata.MountVersion),$($dialectMetadata.MountSecurityOptions),noserverino"
        $linuxClientScript = @'
set -euo pipefail
mkdir -p /mnt/opencifs
mount -t cifs //host.docker.internal/share /mnt/opencifs -o "{0}"
trap 'umount /mnt/opencifs || true' EXIT
mkdir "/mnt/opencifs/{1}"
mkdir "/mnt/opencifs/{1}/nested"
printf '%s' '{2}' > "/mnt/opencifs/{1}/hello.txt"
cat "/mnt/opencifs/{1}/hello.txt" > /tmp/readback.txt
printf '%s' '{2}' > /tmp/expected.txt
cmp /tmp/expected.txt /tmp/readback.txt
head -c {3} /dev/zero | tr '\000' 'A' > /tmp/large.bin
cp /tmp/large.bin "/mnt/opencifs/{1}/large.bin"
cp "/mnt/opencifs/{1}/large.bin" /tmp/large-readback.bin
cmp /tmp/large.bin /tmp/large-readback.bin
mv "/mnt/opencifs/{1}/hello.txt" "/mnt/opencifs/{1}/renamed.txt"
ls -la "/mnt/opencifs/{1}" | tee /tmp/listing.txt
grep -F 'renamed.txt' /tmp/listing.txt >/dev/null
grep -F 'nested' /tmp/listing.txt >/dev/null
set +e
rmdir "/mnt/opencifs/{1}" 2>/tmp/nonempty-rmdir.err
rmdir_exit=$?
set -e
if [ "$rmdir_exit" -eq 0 ]; then
  echo "non-empty directory delete unexpectedly succeeded" >&2
  exit 25
fi
rm "/mnt/opencifs/{1}/renamed.txt"
rm "/mnt/opencifs/{1}/large.bin"
rmdir "/mnt/opencifs/{1}/nested"
rmdir "/mnt/opencifs/{1}"
'@ -f $mountOptions, $remoteDirectory, $payloadText, $LargePayloadLength
        [System.IO.File]::WriteAllText(
            $clientScriptPath,
            ($linuxClientScript -replace "`r`n", "`n"),
            [System.Text.UTF8Encoding]::new($false))

        $dockerClientArguments = @(
            "run",
            "--rm",
            "--privileged",
            "-v", "${dialectArtifactRoot}:/work",
            $ImageName,
            "bash",
            "/work/linux-cifs-client.sh"
        )

        $clientProcess = Start-Process `
            -FilePath "docker" `
            -ArgumentList $dockerClientArguments `
            -WorkingDirectory $repositoryRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $clientLogPath `
            -RedirectStandardError $clientErrorPath `
            -PassThru `
            -Wait

        if ($clientProcess.ExitCode -ne 0) {
            $clientLog = if (Test-Path -LiteralPath $clientLogPath) { Get-Content -Path $clientLogPath -Raw } else { "" }
            $clientError = if (Test-Path -LiteralPath $clientErrorPath) { Get-Content -Path $clientErrorPath -Raw } else { "" }
            $combinedOutput = ($clientLog + [Environment]::NewLine + $clientError).Trim()

            if (
                $dialectMetadata.DialectId -eq "smb2002" -and
                (Test-IsExpectedLegacyDialectMountBlock -CombinedOutput $combinedOutput)) {
                $summary = [ordered]@{
                    dialect = $dialectMetadata.Label
                    dialect_id = $dialectMetadata.DialectId
                    mount_version = $dialectMetadata.MountVersion
                    mount_options = $mountOptions
                    server = "host.docker.internal"
                    port = $port
                    share = "share"
                    directory = $remoteDirectory
                    payload = $payloadText
                    large_payload_length = $LargePayloadLength
                    listing_contains_renamed_file = $null
                    listing_contains_nested_directory = $null
                    non_empty_directory_delete_rejected = $null
                    mount_cifs_version = $mountCifsVersion
                    final_state = [pscustomobject]@{
                        failure = $null
                        skipped = $true
                        skip_reason = "Linux kernel CIFS mount is host-policy-blocked for vers=2.0 on this WSL2/Docker Desktop host before any OpenCIFS traffic reaches the server."
                        skip_detail = $combinedOutput
                    }
                    client_script_path = $clientScriptPath
                    client_log_path = $clientLogPath
                    client_error_path = $clientErrorPath
                    server_config_path = $serverConfigPath
                    server_log_path = $serverLogPath
                    server_error_path = $serverErrorPath
                }

                $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $clientSummaryPath -Encoding UTF8
                $runs.Add($summary)
                continue
            }

            throw "The Linux CIFS client smoke run failed for $($dialectMetadata.Label). Stdout: $clientLog Stderr: $clientError"
        }

        if (Test-Path (Join-Path $shareRoot $remoteDirectory)) {
            throw "The Linux CIFS client smoke left the remote sample-server directory behind for $($dialectMetadata.Label)."
        }

        $summary = [ordered]@{
            dialect = $dialectMetadata.Label
            dialect_id = $dialectMetadata.DialectId
            mount_version = $dialectMetadata.MountVersion
            mount_options = $mountOptions
            server = "host.docker.internal"
            port = $port
            share = "share"
            directory = $remoteDirectory
            payload = $payloadText
            large_payload_length = $LargePayloadLength
            listing_contains_renamed_file = $true
            listing_contains_nested_directory = $true
            non_empty_directory_delete_rejected = $true
            mount_cifs_version = $mountCifsVersion
            final_state = [pscustomobject]@{
                failure = $null
            }
            client_script_path = $clientScriptPath
            client_log_path = $clientLogPath
            client_error_path = $clientErrorPath
            server_config_path = $serverConfigPath
            server_log_path = $serverLogPath
            server_error_path = $serverErrorPath
        }

        $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $clientSummaryPath -Encoding UTF8
        $runs.Add($summary)
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
    environment_path = $environmentPath
    runs = $runs
} | ConvertTo-Json -Depth 8 | Set-Content -Path $resultPath -Encoding UTF8

Write-Output "Linux CIFS interop completed. Evidence:"
Write-Output "  $resultPath"
Write-Output "  $environmentPath"

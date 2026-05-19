param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [string]$SambaImageName = "opencifs-samba-interop:bookworm",
    [string]$DockerContext = "",
    [string]$Dockerfile = "",
    [string]$PeerLabel = "samba-dfs-bookworm"
)

$ErrorActionPreference = "Stop"

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

function Write-LfTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    [System.IO.File]::WriteAllText(
        $Path,
        ($Value -replace "`r`n", "`n"),
        [System.Text.UTF8Encoding]::new($false))
}

if ([string]::IsNullOrWhiteSpace($DockerContext)) {
    $DockerContext = Join-Path $PSScriptRoot "docker\samba-interop"
}

if ([string]::IsNullOrWhiteSpace($Dockerfile)) {
    $Dockerfile = Join-Path $DockerContext "Dockerfile"
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\dfs-interop"
$hostArtifactRoot = Join-Path $repositoryRoot "artifacts\dfs-interop-samba-host"
$startupScriptPath = Join-Path $hostArtifactRoot "start-samba-dfs-server.sh"
$serverLogPath = Join-Path $hostArtifactRoot "samba-dfs-server.log"
$versionsPath = Join-Path $hostArtifactRoot "samba-dfs-versions.txt"
$port = Get-FreeTcpPort
$containerName = "opencifs-samba-dfs-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)

if (Test-Path -LiteralPath $hostArtifactRoot) {
    Remove-Item -LiteralPath $hostArtifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $hostArtifactRoot -Force | Out-Null

$startupScript = @'
#!/bin/bash
set -eu

username="${SAMBA_USERNAME:-alice}"
password="${SAMBA_PASSWORD:-Password123!}"
workgroup="${SAMBA_WORKGROUP:-WORKGROUP}"
namespace_share_name="${SAMBA_NAMESPACE_SHARE_NAME:-namespace}"
namespace_share_path="${SAMBA_NAMESPACE_SHARE_PATH:-/namespace}"
target_share_name="${SAMBA_TARGET_SHARE_NAME:-storage}"
target_share_path="${SAMBA_TARGET_SHARE_PATH:-/storage}"
dfs_link_name="${SAMBA_DFS_LINK_NAME:-link}"
dfs_target_host="${SAMBA_DFS_TARGET_HOST:-localhost}"

mkdir -p /run/samba "${namespace_share_path}" "${target_share_path}"

if ! id -u "${username}" >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin "${username}"
fi

chown -R "${username}:${username}" "${namespace_share_path}" "${target_share_path}"
rm -f "${namespace_share_path}/${dfs_link_name}"
ln -s "msdfs:${dfs_target_host}\\${target_share_name}" "${namespace_share_path}/${dfs_link_name}"

(echo "${password}"; echo "${password}") | smbpasswd -a -s "${username}" >/dev/null

cat > /etc/samba/smb.conf <<EOF
[global]
    workgroup = ${workgroup}
    server string = OpenCifsInteropSambaDfs
    security = user
    map to guest = Never
    ntlm auth = ntlmv2-only
    server min protocol = SMB2_02
    server max protocol = SMB3_11
    server signing = mandatory
    smb ports = 445
    host msdfs = yes
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    log file = /var/log/samba/log.%m
    max log size = 1000
    deadtime = 15

[${namespace_share_name}]
    path = ${namespace_share_path}
    msdfs root = yes
    browseable = yes
    read only = no
    guest ok = no
    valid users = ${username}
    force user = ${username}
    create mask = 0666
    directory mask = 0777

[${target_share_name}]
    path = ${target_share_path}
    browseable = yes
    read only = no
    guest ok = no
    valid users = ${username}
    force user = ${username}
    create mask = 0666
    directory mask = 0777
    locking = yes
    strict locking = yes
EOF

testparm -s /etc/samba/smb.conf >/dev/null
exec smbd --foreground --no-process-group --configfile=/etc/samba/smb.conf
'@

Write-LfTextFile -Path $startupScriptPath -Value $startupScript

& docker build -f $Dockerfile -t $SambaImageName $DockerContext
Assert-LastExitCode "Failed to build the Samba DFS interop image."

$smbclientVersion = (& docker run --rm $SambaImageName smbclient --version).Trim()
Assert-LastExitCode "Failed to read the Samba client version from the DFS interop image."
$smbdVersion = (& docker run --rm $SambaImageName smbd -V).Trim()
Assert-LastExitCode "Failed to read the Samba server version from the DFS interop image."

Set-Content -Path $versionsPath -Value (
    "peer_label=" + $PeerLabel + [Environment]::NewLine +
    "image=" + $SambaImageName + [Environment]::NewLine +
    "dockerfile=" + (Resolve-Path $Dockerfile).Path + [Environment]::NewLine +
    "smbclient=" + $smbclientVersion + [Environment]::NewLine +
    "smbd=" + $smbdVersion)

$resolvedHostArtifactRoot = ((Resolve-Path $hostArtifactRoot).Path).Replace('\', '/')
$dockerRunArguments = @(
    "run",
    "-d",
    "--name", $containerName,
    "-p", ("127.0.0.1:" + $port + ":445"),
    "--mount", ("type=bind,src=" + $resolvedHostArtifactRoot + ",dst=/work"),
    "-e", "SAMBA_USERNAME=alice",
    "-e", "SAMBA_PASSWORD=Password123!",
    "-e", "SAMBA_WORKGROUP=WORKGROUP",
    "-e", "SAMBA_NAMESPACE_SHARE_NAME=namespace",
    "-e", "SAMBA_TARGET_SHARE_NAME=storage",
    "-e", "SAMBA_DFS_LINK_NAME=link",
    "-e", "SAMBA_DFS_TARGET_HOST=localhost",
    $SambaImageName,
    "bash",
    "/work/start-samba-dfs-server.sh"
)

& docker @dockerRunArguments | Out-Null
Assert-LastExitCode "Failed to start the Samba DFS namespace container."

try {
    Wait-ForTcpPort -HostName "127.0.0.1" -Port $port

    & (Join-Path $PSScriptRoot "run-dfs-interop.ps1") `
        -Configuration $Configuration `
        -Framework $Framework `
        -Dialects $Dialects `
        -ServerName "localhost" `
        -ShareName "namespace" `
        -NamespacePath "link" `
        -UserName "alice" `
        -Password "Password123!" `
        -Domain "WORKGROUP" `
        -PeerLabel $PeerLabel `
        -Port $port
    Assert-LastExitCode "The Samba DFS interop harness failed."
}
finally {
    try {
        cmd /c "docker logs $containerName > `"$serverLogPath`" 2>&1"
    }
    catch {
    }

    try {
        & docker rm -f $containerName | Out-Null
    }
    catch {
    }

    if (Test-Path -LiteralPath $artifactRoot) {
        if (Test-Path -LiteralPath $serverLogPath) {
            Copy-Item -LiteralPath $serverLogPath -Destination (Join-Path $artifactRoot "samba-dfs-server.log") -Force
        }

        if (Test-Path -LiteralPath $versionsPath) {
            Copy-Item -LiteralPath $versionsPath -Destination (Join-Path $artifactRoot "samba-dfs-versions.txt") -Force
        }
    }
}

if (-not (Test-Path -LiteralPath $artifactRoot)) {
    throw "The DFS interop harness did not produce an artifact root: $artifactRoot"
}

Write-Output "Samba DFS interop completed."
Write-Output "  $(Join-Path $artifactRoot 'dfs-interop.json')"
Write-Output "  $(Join-Path $artifactRoot 'dfs-environment.json')"

param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302"),
    [switch]$IncludeSmb311Preview,
    [int]$LargePayloadLength = 200000,
    [string[]]$Peers = @("bookworm", "trixie")
)

$ErrorActionPreference = "Stop"

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & powershell -ExecutionPolicy Bypass -File $ScriptPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Get-SambaPeer {
    param([string]$Peer)

    $context = Join-Path $PSScriptRoot "docker\samba-interop"

    switch ($Peer.ToLowerInvariant()) {
        "bookworm" {
            return [pscustomobject]@{
                Label = "debian-bookworm"
                ImageName = "opencifs-samba-interop:bookworm"
                Dockerfile = Join-Path $context "Dockerfile"
            }
        }
        "trixie" {
            return [pscustomobject]@{
                Label = "debian-trixie"
                ImageName = "opencifs-samba-interop:trixie"
                Dockerfile = Join-Path $context "Dockerfile.trixie"
            }
        }
        default {
            throw "Unsupported Samba peer '$Peer'. Supported peers: bookworm, trixie."
        }
    }
}

$scriptPath = Join-Path $PSScriptRoot "run-samba-interop.ps1"
$contextPath = Join-Path $PSScriptRoot "docker\samba-interop"
$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$sourceArtifactRoot = Join-Path $repositoryRoot "artifacts\samba-interop"
$matrixArtifactRoot = Join-Path $repositoryRoot "artifacts\samba-peer-matrix"

if (Test-Path $matrixArtifactRoot) {
    Remove-Item -LiteralPath $matrixArtifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $matrixArtifactRoot -Force | Out-Null

foreach ($peerName in $Peers) {
    $peer = Get-SambaPeer -Peer $peerName
    $arguments = @(
        "-Configuration", $Configuration,
        "-Framework", $Framework,
        "-Dialects"
    ) + $Dialects + @(
        "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        "-SambaImageName", $peer.ImageName,
        "-DockerContext", $contextPath,
        "-Dockerfile", $peer.Dockerfile,
        "-PeerLabel", $peer.Label
    )

    if ($IncludeSmb311Preview) {
        $arguments += "-IncludeSmb311Preview"
    }

    Invoke-ChildPowerShellScript -ScriptPath $scriptPath -Arguments $arguments

    $peerArtifactRoot = Join-Path $matrixArtifactRoot $peer.Label
    if (Test-Path $peerArtifactRoot) {
        Remove-Item -LiteralPath $peerArtifactRoot -Recurse -Force
    }

    Copy-Item -LiteralPath $sourceArtifactRoot -Destination $peerArtifactRoot -Recurse -Force
}

Write-Output "Samba peer matrix completed. Evidence:"
Write-Output "  $matrixArtifactRoot"

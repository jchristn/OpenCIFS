param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302")
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "run-local-windows-server-interop.ps1 must be run from an elevated PowerShell session so it can create and remove a temporary local SMB share and account."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\windows-server-local-share"
$shareRoot = Join-Path $artifactRoot "share"
$metadataPath = Join-Path $artifactRoot "local-share-provisioning.json"
$computerName = $env:COMPUTERNAME
$shareName = "opencifsws" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
$userName = "opencifsws" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
$password = "P@" + [Guid]::NewGuid().ToString("N") + "!"
$qualifiedUserName = $computerName + "\" + $userName
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$shareCreated = $false
$userCreated = $false

if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    computer_name = $computerName
    share_name = $shareName
    user_name = $userName
    share_root = $shareRoot
    dialects = $Dialects
} | ConvertTo-Json -Depth 4 | Set-Content -Path $metadataPath -Encoding UTF8

try {
    New-LocalUser `
        -Name $userName `
        -Password $securePassword `
        -FullName "OpenCIFS Windows Server Interop" `
        -Description "Temporary local account for OpenCIFS Windows SMB server interop." `
        -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
    $userCreated = $true

    & icacls $shareRoot /grant ($qualifiedUserName + ":(OI)(CI)M") | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant NTFS permissions on the temporary Windows share root."
    }

    New-SmbShare `
        -Name $shareName `
        -Path $shareRoot `
        -FullAccess @($qualifiedUserName, "Administrators") | Out-Null
    $shareCreated = $true

    & (Join-Path $PSScriptRoot "run-windows-server-interop.ps1") `
        -Configuration $Configuration `
        -Framework $Framework `
        -Dialects $Dialects `
        -ServerName "127.0.0.1" `
        -ShareName $shareName `
        -UserName $userName `
        -Password $password `
        -Domain $computerName
}
finally {
    if ($shareCreated) {
        Remove-SmbShare -Name $shareName -Force
    }

    if ($userCreated) {
        Remove-LocalUser -Name $userName
    }
}

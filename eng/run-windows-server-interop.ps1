param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$ServerName = "",
    [string]$ShareName = "",
    [string]$UserName = "",
    [string]$Password = "",
    [string]$Domain = "",
    [int]$Port = 0,
    [string[]]$Dialects = @("Smb2002", "Smb21", "Smb302")
)

$ErrorActionPreference = "Stop"

function Get-ConfiguredValue {
    param(
        [Parameter(Mandatory = $true)][string]$ParameterValue,
        [Parameter(Mandatory = $true)][string]$EnvironmentVariableName
    )

    if (-not [string]::IsNullOrWhiteSpace($ParameterValue)) {
        return $ParameterValue
    }

    return [Environment]::GetEnvironmentVariable($EnvironmentVariableName)
}

function Get-RequiredConfiguredValue {
    param(
        [Parameter(Mandatory = $true)][string]$ParameterValue,
        [Parameter(Mandatory = $true)][string]$ParameterName,
        [Parameter(Mandatory = $true)][string]$EnvironmentVariableName
    )

    $resolvedValue = Get-ConfiguredValue -ParameterValue $ParameterValue -EnvironmentVariableName $EnvironmentVariableName
    if ([string]::IsNullOrWhiteSpace($resolvedValue)) {
        throw "$ParameterName is required. Supply -$ParameterName or set $EnvironmentVariableName."
    }

    return $resolvedValue
}

$ServerName = Get-RequiredConfiguredValue -ParameterValue $ServerName -ParameterName "ServerName" -EnvironmentVariableName "OPENCIFS_WINDOWS_SERVER_NAME"
$ShareName = Get-RequiredConfiguredValue -ParameterValue $ShareName -ParameterName "ShareName" -EnvironmentVariableName "OPENCIFS_WINDOWS_SERVER_SHARE_NAME"
$UserName = Get-RequiredConfiguredValue -ParameterValue $UserName -ParameterName "UserName" -EnvironmentVariableName "OPENCIFS_WINDOWS_SERVER_USER_NAME"
$Password = Get-RequiredConfiguredValue -ParameterValue $Password -ParameterName "Password" -EnvironmentVariableName "OPENCIFS_WINDOWS_SERVER_PASSWORD"
$Domain = Get-ConfiguredValue -ParameterValue $Domain -EnvironmentVariableName "OPENCIFS_WINDOWS_SERVER_DOMAIN"

if ($Port -le 0) {
    $environmentPort = [Environment]::GetEnvironmentVariable("OPENCIFS_WINDOWS_SERVER_PORT")
    if ([string]::IsNullOrWhiteSpace($environmentPort)) {
        $Port = 445
    }
    else {
        $parsedPort = 0
        if (-not [int]::TryParse($environmentPort, [ref]$parsedPort) -or $parsedPort -le 0) {
            throw "OPENCIFS_WINDOWS_SERVER_PORT must be a positive integer when supplied."
        }

        $Port = $parsedPort
    }
}

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\windows-server-interop"
$resultPath = Join-Path $artifactRoot "windows-server-interop.json"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

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
                PreferEncryption = $false
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                PreferEncryption = $false
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                PreferEncryption = $true
            }
        }
        default {
            throw "Unsupported Windows server interop dialect '$Dialect'."
        }
    }
}

function Invoke-WindowsServerInteropRun {
    param(
        [Parameter(Mandatory = $true)]$DialectMetadata
    )

    $runRoot = Join-Path $artifactRoot $DialectMetadata.DialectId
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

    $clientInputPath = Join-Path $runRoot "client-input.txt"
    $clientOutputPath = Join-Path $runRoot "client-output.txt"
    $clientErrorPath = Join-Path $runRoot "client-error.txt"
    $downloadPath = Join-Path $runRoot "download.txt"
    $testRoot = "opencifs-windows-server-" + $DialectMetadata.DialectId + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $expectedText = "Hello from OpenCIFS Windows server interop " + $DialectMetadata.DialectId
    $encryptionSwitch = if ($DialectMetadata.PreferEncryption) { "on" } else { "off" }

    $commands = New-Object System.Collections.Generic.List[string]
    $commands.Add("server $ServerName")
    $commands.Add("port $Port")
    $commands.Add("user $UserName")

    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $commands.Add("domain $Domain")
    }

    $commands.Add("password $Password")
    $commands.Add("dialects $($DialectMetadata.Dialect) $($DialectMetadata.Dialect)")
    $commands.Add("signing on")
    $commands.Add("encryption $encryptionSwitch")
    $commands.Add("connect")
    $commands.Add("status")
    $commands.Add("open $ShareName")
    $commands.Add("mkdir /$testRoot")
    $commands.Add("write-text /$testRoot/hello.txt $expectedText")
    $commands.Add("ls /$testRoot")
    $commands.Add("stat /$testRoot/hello.txt")
    $commands.Add("cat /$testRoot/hello.txt")
    $commands.Add("mv /$testRoot/hello.txt /$testRoot/renamed.txt")
    $commands.Add("get /$testRoot/renamed.txt ""$downloadPath""")
    $commands.Add("rm /$testRoot/renamed.txt")
    $commands.Add("rmdir /$testRoot")
    $commands.Add("close")
    $commands.Add("disconnect")
    $commands.Add("q")
    $commands | Out-File -FilePath $clientInputPath -Encoding ascii

    $clientArguments = @(
        "run",
        "--project", "src/OpenCIFS.TestClient/OpenCIFS.TestClient.csproj",
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build"
    )

    try {
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

        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Connected and authenticated."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText ("Negotiated Dialect: " + $DialectMetadata.Dialect)
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Opened share '$ShareName'."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Created directory /$testRoot."
        Assert-OutputContains -Path $clientOutputPath -ExpectedText $expectedText
        Assert-OutputContains -Path $clientOutputPath -ExpectedText "[OK] Deleted directory /$testRoot."

        if (-not (Test-Path $downloadPath)) {
            throw "The Windows server interop run did not produce the downloaded file artifact for $($DialectMetadata.DialectId)."
        }

        $downloadedText = [string](Get-Content -Path $downloadPath -Raw)
        if ($downloadedText -ne $expectedText) {
            throw "The downloaded file text did not match the expected payload for $($DialectMetadata.DialectId)."
        }

        return [pscustomobject]@{
            dialect = $DialectMetadata.Dialect
            dialect_id = $DialectMetadata.DialectId
            label = $DialectMetadata.Label
            server_name = $ServerName
            share_name = $ShareName
            port = $Port
            require_signing = $true
            prefer_encryption = [bool]$DialectMetadata.PreferEncryption
            operations = @(
                "negotiate",
                "session_setup",
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
            server_name = $ServerName
            share_name = $ShareName
            port = $Port
            require_signing = $true
            prefer_encryption = [bool]$DialectMetadata.PreferEncryption
            operations = @()
            final_state = [pscustomobject]@{
                failure = $_.Exception.Message
            }
            client_output_path = $clientOutputPath
            client_error_path = $clientErrorPath
            download_path = $downloadPath
        }
    }
}

$environmentPath = Join-Path $artifactRoot "windows-server-environment.json"
[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    client_machine = $env:COMPUTERNAME
    os_version = [System.Environment]::OSVersion.VersionString
    server_name = $ServerName
    share_name = $ShareName
    port = $Port
    domain_supplied = -not [string]::IsNullOrWhiteSpace($Domain)
    dialects = $Dialects
} | ConvertTo-Json -Depth 4 | Set-Content -Path $environmentPath -Encoding UTF8

$runs = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $metadata = Get-DialectMetadata -Dialect $dialect
    $run = Invoke-WindowsServerInteropRun -DialectMetadata $metadata
    $runs.Add($run)

    if (-not [string]::IsNullOrWhiteSpace([string]$run.final_state.failure)) {
        [pscustomobject]@{
            configuration = $Configuration
            framework = $Framework
            peer_topology = "OpenCIFS.TestClient -> Windows SMB server"
            environment_path = $environmentPath
            runs = $runs
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8
        throw "Windows server interop failed for $($metadata.DialectId): $($run.final_state.failure)"
    }
}

[pscustomobject]@{
    configuration = $Configuration
    framework = $Framework
    peer_topology = "OpenCIFS.TestClient -> Windows SMB server"
    environment_path = $environmentPath
    runs = $runs
} | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8

Write-Output "Windows server interop completed."
Write-Output "  $resultPath"
Write-Output "  $environmentPath"

param(
    [string]$Configuration = "Release",
    [string]$Framework = "net8.0",
    [int]$LargePayloadLength = 1048576,
    [int]$RealClientIterations = 2,
    [int]$SambaIterations = 2,
    [int]$WindowsIterations = 1,
    [int]$SoakWorkerCount = 6,
    [int]$SoakWorkerIterations = 4,
    [int]$SoakDurableIterations = 6,
    [int]$SoakOplockIterations = 6,
    [int]$SoakLeaseIterations = 6,
    [int]$SoakMinimumDurationSeconds = 90
)

$ErrorActionPreference = "Stop"

if ($LargePayloadLength -lt 200000) {
    throw "LargePayloadLength must be at least 200000 bytes for the deeper nightly interop path."
}

if ($RealClientIterations -lt 1 -or $SambaIterations -lt 1 -or $WindowsIterations -lt 1) {
    throw "RealClientIterations, SambaIterations, and WindowsIterations must all be at least 1."
}

if ($SoakWorkerCount -lt 1 -or
    $SoakWorkerIterations -lt 1 -or
    $SoakDurableIterations -lt 1 -or
    $SoakOplockIterations -lt 1 -or
    $SoakLeaseIterations -lt 1 -or
    $SoakMinimumDurationSeconds -lt 1) {
    throw "Nightly soak parameters must all be positive."
}

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & powershell -ExecutionPolicy Bypass -File $ScriptPath @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "Child script '$ScriptPath' exited with code $LASTEXITCODE."
    }
}

function Copy-ArtifactSubset {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )

    New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null

    foreach ($relativePath in $RelativePaths) {
        $sourcePath = Join-Path $SourceRoot $relativePath

        if (-not (Test-Path -LiteralPath $sourcePath)) {
            throw "Expected artifact path '$sourcePath' was not produced."
        }

        $destinationPath = Join-Path $DestinationRoot $relativePath
        $destinationParent = Split-Path -Path $destinationPath -Parent

        if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
            New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
        }

        if ((Get-Item -LiteralPath $sourcePath) -is [System.IO.DirectoryInfo]) {
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Recurse -Force
        }
        else {
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
        }
    }
}

function Get-ArtifactRunDialectIds {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][string]$ArtifactLabel
    )

    $dialectIds = New-Object System.Collections.Generic.List[string]

    foreach ($run in @($Document.runs)) {
        if ($null -ne $run.dialect_id) {
            $dialectIds.Add([string]$run.dialect_id)
            continue
        }

        if ($null -ne $run.summary -and $null -ne $run.summary.dialect_id) {
            $dialectIds.Add([string]$run.summary.dialect_id)
            continue
        }

        throw "$ArtifactLabel contains a run without a dialect_id."
    }

    $uniqueDialectIds = @($dialectIds | Sort-Object -Unique)

    foreach ($requiredDialectId in @("smb2002", "smb21")) {
        if ($uniqueDialectIds -notcontains $requiredDialectId) {
            throw "$ArtifactLabel is missing the required dialect run '$requiredDialectId'."
        }
    }

    return $uniqueDialectIds
}

function Assert-ArtifactLargePayloadLength {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][int]$ExpectedLargePayloadLength,
        [Parameter(Mandatory = $true)][string]$ArtifactLabel
    )

    foreach ($run in @($Document.runs)) {
        $payloadLength = $null

        if ($null -ne $run.summary) {
            if ($null -ne $run.summary.large_payload_length) {
                $payloadLength = [int]$run.summary.large_payload_length
            }
            elseif ($null -ne $run.summary.LargePayloadLength) {
                $payloadLength = [int]$run.summary.LargePayloadLength
            }
        }

        if ($null -eq $payloadLength) {
            if ($null -ne $run.large_payload_length) {
                $payloadLength = [int]$run.large_payload_length
            }
            elseif ($null -ne $run.LargePayloadLength) {
                $payloadLength = [int]$run.LargePayloadLength
            }
        }

        if ($null -eq $payloadLength) {
            throw "$ArtifactLabel contains a run without a large_payload_length value."
        }

        if ($payloadLength -ne $ExpectedLargePayloadLength) {
            throw "$ArtifactLabel reported large_payload_length=$payloadLength instead of $ExpectedLargePayloadLength."
        }
    }
}

function Get-ArtifactPathSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )

    return $RelativePaths | ForEach-Object { Join-Path $Root $_ }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\nightly-interop"
$resultPath = Join-Path $artifactRoot "nightly-interop.json"

if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

$realClientScriptPath = Join-Path $PSScriptRoot "run-real-client-interop.ps1"
$sambaScriptPath = Join-Path $PSScriptRoot "run-samba-interop.ps1"
$windowsScriptPath = Join-Path $PSScriptRoot "run-windows-client-interop.ps1"
$soakScriptPath = Join-Path $PSScriptRoot "run-soak-smoke.ps1"

$realClientArtifactSourceRoot = Join-Path $repositoryRoot "artifacts\real-client-interop"
$sambaArtifactSourceRoot = Join-Path $repositoryRoot "artifacts\samba-interop"
$windowsArtifactSourceRoot = Join-Path $repositoryRoot "artifacts\windows-client-interop"
$soakArtifactSourceRoot = Join-Path $repositoryRoot "artifacts\soak-smoke"

$realClientRelativePaths = @(
    "real-client-smoke.json",
    "sample-server.config.txt",
    "smb2002",
    "smb21"
)
$sambaRelativePaths = @(
    "open-cifs-client-to-samba.json",
    "sample-server-samba-client.json",
    "sample-server.config.txt",
    "samba-versions.txt",
    "smb2002",
    "smb21"
)
$windowsRelativePaths = @(
    "windows-client-smoke.json",
    "windows-client-environment.json",
    "sample-server.config.txt",
    "smb2002",
    "smb21"
)

$realClientRuns = New-Object System.Collections.Generic.List[object]
$sambaRuns = New-Object System.Collections.Generic.List[object]
$windowsRuns = New-Object System.Collections.Generic.List[object]

for ($iteration = 1; $iteration -le $RealClientIterations; $iteration++) {
    Invoke-ChildPowerShellScript -ScriptPath $realClientScriptPath -Arguments @(
        "-Configuration", $Configuration,
        "-Framework", $Framework,
        "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    )

    $destinationRoot = Join-Path $artifactRoot ("real-client\iteration-{0:D2}" -f $iteration)
    Copy-ArtifactSubset -SourceRoot $realClientArtifactSourceRoot -DestinationRoot $destinationRoot -RelativePaths $realClientRelativePaths

    $documentPath = Join-Path $destinationRoot "real-client-smoke.json"
    $document = Get-Content -Path $documentPath -Raw | ConvertFrom-Json
    $dialectIds = Get-ArtifactRunDialectIds -Document $document -ArtifactLabel ("real-client nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    Assert-ArtifactLargePayloadLength -Document $document -ExpectedLargePayloadLength $LargePayloadLength -ArtifactLabel ("real-client nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))

    $realClientRuns.Add([pscustomobject]@{
        iteration = $iteration
        dialect_ids = $dialectIds
        artifact_paths = Get-ArtifactPathSummary -Root $destinationRoot -RelativePaths $realClientRelativePaths
        summary = $document
    })
}

for ($iteration = 1; $iteration -le $SambaIterations; $iteration++) {
    Invoke-ChildPowerShellScript -ScriptPath $sambaScriptPath -Arguments @(
        "-Configuration", $Configuration,
        "-Framework", $Framework,
        "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    )

    $destinationRoot = Join-Path $artifactRoot ("samba\iteration-{0:D2}" -f $iteration)
    Copy-ArtifactSubset -SourceRoot $sambaArtifactSourceRoot -DestinationRoot $destinationRoot -RelativePaths $sambaRelativePaths

    $clientDocumentPath = Join-Path $destinationRoot "open-cifs-client-to-samba.json"
    $serverDocumentPath = Join-Path $destinationRoot "sample-server-samba-client.json"
    $clientDocument = Get-Content -Path $clientDocumentPath -Raw | ConvertFrom-Json
    $serverDocument = Get-Content -Path $serverDocumentPath -Raw | ConvertFrom-Json

    $clientDialects = Get-ArtifactRunDialectIds -Document $clientDocument -ArtifactLabel ("samba client nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    $serverDialects = Get-ArtifactRunDialectIds -Document $serverDocument -ArtifactLabel ("sample-server Samba nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    Assert-ArtifactLargePayloadLength -Document $clientDocument -ExpectedLargePayloadLength $LargePayloadLength -ArtifactLabel ("samba client nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    Assert-ArtifactLargePayloadLength -Document $serverDocument -ExpectedLargePayloadLength $LargePayloadLength -ArtifactLabel ("sample-server Samba nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))

    $sambaRuns.Add([pscustomobject]@{
        iteration = $iteration
        open_cifs_client_dialect_ids = $clientDialects
        sample_server_dialect_ids = $serverDialects
        artifact_paths = Get-ArtifactPathSummary -Root $destinationRoot -RelativePaths $sambaRelativePaths
        open_cifs_client_summary = $clientDocument
        sample_server_summary = $serverDocument
    })
}

for ($iteration = 1; $iteration -le $WindowsIterations; $iteration++) {
    Invoke-ChildPowerShellScript -ScriptPath $windowsScriptPath -Arguments @(
        "-Configuration", $Configuration,
        "-Framework", $Framework,
        "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    )

    $destinationRoot = Join-Path $artifactRoot ("windows\iteration-{0:D2}" -f $iteration)
    Copy-ArtifactSubset -SourceRoot $windowsArtifactSourceRoot -DestinationRoot $destinationRoot -RelativePaths $windowsRelativePaths

    $documentPath = Join-Path $destinationRoot "windows-client-smoke.json"
    $document = Get-Content -Path $documentPath -Raw | ConvertFrom-Json
    $dialectIds = Get-ArtifactRunDialectIds -Document $document -ArtifactLabel ("windows nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    Assert-ArtifactLargePayloadLength -Document $document -ExpectedLargePayloadLength $LargePayloadLength -ArtifactLabel ("windows nightly iteration " + $iteration.ToString([System.Globalization.CultureInfo]::InvariantCulture))

    $windowsRuns.Add([pscustomobject]@{
        iteration = $iteration
        dialect_ids = $dialectIds
        artifact_paths = Get-ArtifactPathSummary -Root $destinationRoot -RelativePaths $windowsRelativePaths
        summary = $document
    })
}

Invoke-ChildPowerShellScript -ScriptPath $soakScriptPath -Arguments @(
    "-Configuration", $Configuration,
    "-Framework", $Framework,
    "-WorkerCount", $SoakWorkerCount.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-WorkerIterations", $SoakWorkerIterations.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-DurableIterations", $SoakDurableIterations.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-OplockIterations", $SoakOplockIterations.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-LeaseIterations", $SoakLeaseIterations.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-MinimumDurationSeconds", $SoakMinimumDurationSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "-LargePayloadLength", $LargePayloadLength.ToString([System.Globalization.CultureInfo]::InvariantCulture)
)

$soakDestinationRoot = Join-Path $artifactRoot "soak"
Copy-ArtifactSubset -SourceRoot $soakArtifactSourceRoot -DestinationRoot $soakDestinationRoot -RelativePaths @("soak-smoke.json")
$soakDocumentPath = Join-Path $soakDestinationRoot "soak-smoke.json"
$soakDocument = Get-Content -Path $soakDocumentPath -Raw | ConvertFrom-Json

if ($soakDocument.MinimumDialect -ne "Smb21" -or $soakDocument.MaximumDialect -ne "Smb21") {
    throw "The nightly soak artifact did not report the expected SMB 2.1-only dialect scope."
}

if ([int]$soakDocument.LargePayloadLength -ne $LargePayloadLength) {
    throw "The nightly soak artifact reported LargePayloadLength=$($soakDocument.LargePayloadLength) instead of $LargePayloadLength."
}

if ([int]$soakDocument.TotalDurableReconnects -lt $SoakDurableIterations) {
    throw "The nightly soak artifact did not report the expected durable reconnect coverage floor."
}

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    configuration = $Configuration
    framework = $Framework
    large_payload_length = $LargePayloadLength
    real_client_iterations = $RealClientIterations
    samba_iterations = $SambaIterations
    windows_iterations = $WindowsIterations
    soak = [pscustomobject]@{
        artifact_paths = Get-ArtifactPathSummary -Root $soakDestinationRoot -RelativePaths @("soak-smoke.json")
        summary = $soakDocument
    }
    real_client_runs = $realClientRuns
    samba_runs = $sambaRuns
    windows_runs = $windowsRuns
    encryption_status = "bounded-smb302"
    notes = @(
        "Nightly-style current-dialect automation now reruns the Python real-client, Samba, and native Windows three-dialect interop stacks across SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2 with a larger bounded payload.",
        "The composed nightly artifact also includes a stronger SMB 2.1 soak that exercises durable reconnect, exclusive oplock breaks, lease breaks, and large-I/O churn on the managed path.",
        "Secure negotiate, durable-handle v2, SMB 3.1.1 negotiation, and broader SMB 3.x nightly coverage remain backlog."
    )
} | ConvertTo-Json -Depth 12 | Set-Content -Path $resultPath -Encoding UTF8

Write-Host "Nightly interop validation completed. Evidence:"
Write-Host "  $resultPath"

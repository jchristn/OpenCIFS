param(
    [string]$Configuration = "Release",
    [string]$AsOfDate = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AsOfDate)) {
    $AsOfDate = (Get-Date).ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture)
}

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\release-gates"
$resultPath = Join-Path $artifactRoot "release-gates.json"
$coverageMatrixPath = Join-Path $repositoryRoot "docs\coverage-matrix.md"
$interopMatrixPath = Join-Path $repositoryRoot "docs\interop-matrix.md"
$buildValidatorProjectPath = Join-Path $repositoryRoot "eng\OpenCIFS.Build\OpenCIFS.Build.csproj"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

function Invoke-BuildValidator {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Path
    )

    dotnet run --project $buildValidatorProjectPath --configuration $Configuration --no-launch-profile -- $Command $Path
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Convert-MarkdownRowToColumns {
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )

    $trimmed = $Line.Trim()

    if ($trimmed.StartsWith("|", [System.StringComparison]::Ordinal)) {
        $trimmed = $trimmed.Substring(1)
    }

    if ($trimmed.EndsWith("|", [System.StringComparison]::Ordinal)) {
        $trimmed = $trimmed.Substring(0, $trimmed.Length - 1)
    }

    return $trimmed.Split('|') | ForEach-Object { $_.Trim() }
}

function Get-MarkdownTableRows {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$HeaderMarker,
        [Parameter(Mandatory = $true)][int]$ExpectedColumnCount
    )

    $lines = Get-Content -Path $Path
    $headerIndex = -1

    for ($index = 0; $index -lt $lines.Length; $index++) {
        if ($lines[$index].IndexOf($HeaderMarker, [System.StringComparison]::Ordinal) -ge 0) {
            $headerIndex = $index
            break
        }
    }

    if ($headerIndex -lt 0) {
        throw "Markdown header marker '$HeaderMarker' was not found in $Path."
    }

    $rows = New-Object System.Collections.Generic.List[object]

    for ($lineIndex = $headerIndex + 2; $lineIndex -lt $lines.Length; $lineIndex++) {
        $line = $lines[$lineIndex]

        if ([string]::IsNullOrWhiteSpace($line) -or -not $line.TrimStart().StartsWith("|", [System.StringComparison]::Ordinal)) {
            continue
        }

        $columns = Convert-MarkdownRowToColumns -Line $line

        if ($columns.Length -ne $ExpectedColumnCount) {
            throw "Markdown row $($lineIndex + 1) in $Path does not contain $ExpectedColumnCount columns."
        }

        $rows.Add([pscustomobject]@{
            LineNumber = $lineIndex + 1
            Columns = $columns
        })
    }

    return $rows
}

function Get-EvidenceEntries {
    param(
        [Parameter(Mandatory = $true)][string]$EvidenceColumn
    )

    if ($EvidenceColumn -eq "n/a") {
        return @()
    }

    return $EvidenceColumn.Split(',') |
        ForEach-Object { $_.Trim().Trim('`') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

function Get-ArtifactDialectIds {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $document = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $dialectIds = @()

    if ($null -ne $document.runs) {
        foreach ($run in $document.runs) {
            if ($null -ne $run.dialect_id) {
                $dialectIds += [string]$run.dialect_id
            }
            elseif ($null -ne $run.summary -and $null -ne $run.summary.dialect_id) {
                $dialectIds += [string]$run.summary.dialect_id
            }
        }
    }

    return $dialectIds | Sort-Object -Unique
}

function Get-ArtifactRuns {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $document = Get-Content -Path $Path -Raw | ConvertFrom-Json

    if ($null -eq $document.runs) {
        throw "The artifact does not contain a 'runs' payload."
    }

    return @($document.runs)
}

function Get-ArtifactRunDialectId {
    param(
        [Parameter(Mandatory = $true)]$Run
    )

    if ($null -ne $Run.dialect_id) {
        return [string]$Run.dialect_id
    }

    if ($null -ne $Run.summary -and $null -ne $Run.summary.dialect_id) {
        return [string]$Run.summary.dialect_id
    }

    throw "The artifact run does not expose a dialect identifier."
}

function Get-ArtifactRunFailure {
    param(
        [Parameter(Mandatory = $true)]$Run
    )

    if ($null -ne $Run.final_state -and -not [string]::IsNullOrWhiteSpace([string]$Run.final_state.failure)) {
        return [string]$Run.final_state.failure
    }

    return $null
}

Invoke-BuildValidator -Command "validate-coverage" -Path $coverageMatrixPath
Invoke-BuildValidator -Command "validate-interop" -Path $interopMatrixPath
Invoke-BuildValidator -Command "validate-package-claims" -Path $repositoryRoot
Invoke-BuildValidator -Command "validate-source-audit" -Path $repositoryRoot

$errors = New-Object System.Collections.Generic.List[string]
$validatedEvidencePaths = New-Object System.Collections.Generic.List[string]

$requiredArtifactPaths = @(
    "artifacts\package-smoke\package-metadata.json",
    "artifacts\package-smoke\package-smoke.json",
    "artifacts\readme-smoke\readme-smoke.json",
    "artifacts\test-console-smoke\test-console-smoke.json",
    "artifacts\published-sample-smoke\published-sample-smoke.json",
    "artifacts\soak-smoke\soak-smoke.json",
    "artifacts\real-client-interop\real-client-smoke.json",
    "artifacts\samba-interop\open-cifs-client-to-samba.json",
    "artifacts\samba-interop\sample-server-samba-client.json",
    "artifacts\windows-client-interop\windows-client-smoke.json",
    "artifacts\windows-client-interop\windows-client-environment.json"
)

for ($artifactIndex = 0; $artifactIndex -lt $requiredArtifactPaths.Length; $artifactIndex++) {
    $artifactPath = Join-Path $repositoryRoot $requiredArtifactPaths[$artifactIndex]

    if (-not (Test-Path $artifactPath)) {
        $errors.Add("Required release artifact was not found: $artifactPath.")
    }
}

$publishedSampleSmokePath = Join-Path $repositoryRoot "artifacts\published-sample-smoke\published-sample-smoke.json"
if (Test-Path $publishedSampleSmokePath) {
    try {
        $publishedSampleSmoke = Get-Content -Path $publishedSampleSmokePath -Raw | ConvertFrom-Json
    }
    catch {
        $errors.Add("The published-sample-smoke artifact could not be parsed as JSON: $publishedSampleSmokePath.")
        $publishedSampleSmoke = $null
    }

    if ($null -ne $publishedSampleSmoke) {
        $requiredPublishedSampleFields = @(
            "publish_manifest_path",
            "launcher_path",
            "print_launcher_path",
            "validate_launcher_path",
            "quickstart_path"
        )

        foreach ($field in $requiredPublishedSampleFields) {
            $value = $publishedSampleSmoke.$field
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
                $errors.Add("The published-sample-smoke artifact is missing '$field'.")
                continue
            }

            if (-not (Test-Path ([string]$value))) {
                $errors.Add("The published-sample-smoke artifact references a missing path: $value.")
            }
        }

        try {
            $publishedSampleRuns = Get-ArtifactRuns -Path $publishedSampleSmokePath
        }
        catch {
            $errors.Add($_.Exception.Message)
            $publishedSampleRuns = @()
        }

        $publishedSampleDialectIds = @()

        foreach ($run in $publishedSampleRuns) {
            try {
                $publishedSampleDialectIds += Get-ArtifactRunDialectId -Run $run
            }
            catch {
                $errors.Add($_.Exception.Message)
                continue
            }

            $publishedSampleFailure = Get-ArtifactRunFailure -Run $run
            if ($null -ne $publishedSampleFailure) {
                $errors.Add("The published-sample-smoke artifact reports a failure for dialect '$((Get-ArtifactRunDialectId -Run $run))': $publishedSampleFailure")
            }
        }

        foreach ($requiredDialect in @("smb2002", "smb21")) {
            if ($publishedSampleDialectIds -notcontains $requiredDialect) {
                $errors.Add("The published-sample-smoke artifact is missing the required dialect run '$requiredDialect'.")
            }
        }
    }
}

$testConsoleSmokePath = Join-Path $repositoryRoot "artifacts\test-console-smoke\test-console-smoke.json"
if (Test-Path $testConsoleSmokePath) {
    try {
        $testConsoleSmoke = Get-Content -Path $testConsoleSmokePath -Raw | ConvertFrom-Json
    }
    catch {
        $errors.Add("The test-console-smoke artifact could not be parsed as JSON: $testConsoleSmokePath.")
        $testConsoleSmoke = $null
    }

    if ($null -ne $testConsoleSmoke) {
        if (-not [bool]$testConsoleSmoke.Succeeded) {
            $errors.Add("The test-console-smoke artifact does not report success.")
        }

        if ([string]::IsNullOrWhiteSpace([string]$testConsoleSmoke.ShareName)) {
            $errors.Add("The test-console-smoke artifact does not report a share name.")
        }

        if ([int]$testConsoleSmoke.Port -le 0) {
            $errors.Add("The test-console-smoke artifact does not report a valid TCP port.")
        }

        foreach ($pathField in @("ServerOutputPath", "ServerErrorPath", "ClientOutputPath", "ClientErrorPath", "DownloadPath")) {
            $value = [string]$testConsoleSmoke.$pathField
            if ([string]::IsNullOrWhiteSpace($value)) {
                $errors.Add("The test-console-smoke artifact is missing '$pathField'.")
                continue
            }

            if (-not (Test-Path $value)) {
                $errors.Add("The test-console-smoke artifact references a missing path: $value.")
            }
        }

        if ([string]$testConsoleSmoke.DownloadedText -ne [string]$testConsoleSmoke.ExpectedText) {
            $errors.Add("The test-console-smoke artifact reports a round-trip payload mismatch.")
        }
    }
}

$soakSmokePath = Join-Path $repositoryRoot "artifacts\soak-smoke\soak-smoke.json"
if (Test-Path $soakSmokePath) {
    try {
        $soakSmoke = Get-Content -Path $soakSmokePath -Raw | ConvertFrom-Json
    }
    catch {
        $errors.Add("The soak-smoke artifact could not be parsed as JSON: $soakSmokePath.")
        $soakSmoke = $null
    }

    if ($null -ne $soakSmoke) {
        if ($soakSmoke.MinimumDialect -ne "Smb21" -or $soakSmoke.MaximumDialect -ne "Smb21") {
            $errors.Add("The soak-smoke artifact does not report bounded SMB 2.1 execution.")
        }

        if (
            [int]$soakSmoke.WorkerCount -lt 1 -or
            [int]$soakSmoke.WorkerIterations -lt 1 -or
            [int]$soakSmoke.DurableIterations -lt 1 -or
            [int]$soakSmoke.OplockIterations -lt 1 -or
            [int]$soakSmoke.LeaseIterations -lt 1 -or
            [int]$soakSmoke.MinimumDurationSeconds -lt 1) {
            $errors.Add("The soak-smoke artifact does not report positive worker, churn, and duration configuration values.")
        }

        if ([int]$soakSmoke.LargePayloadLength -lt 65536) {
            $errors.Add("The soak-smoke artifact large payload length is below the bounded large-I/O threshold.")
        }

        $expectedPrimaryClientConnections = [int]$soakSmoke.WorkerCount * [int]$soakSmoke.WorkerIterations
        $expectedNonEmptyDeleteRejections = $expectedPrimaryClientConnections
        $expectedDurableReconnects = [int]$soakSmoke.DurableIterations
        $expectedOplockBreaks = [int]$soakSmoke.OplockIterations
        $expectedLeaseBreaks = [int]$soakSmoke.LeaseIterations

        if ([int]$soakSmoke.ElapsedMilliseconds -lt ([int]$soakSmoke.MinimumDurationSeconds * 1000)) {
            $errors.Add("The soak-smoke artifact completed before the configured minimum duration elapsed.")
        }

        if ([int]$soakSmoke.TotalPrimaryClientConnections -lt $expectedPrimaryClientConnections) {
            $errors.Add("The soak-smoke artifact reports fewer primary-client connections than expected for the configured worker matrix.")
        }

        if ([int]$soakSmoke.TotalLargeRoundTrips -lt $expectedPrimaryClientConnections) {
            $errors.Add("The soak-smoke artifact reports fewer large round trips than expected for the configured worker matrix.")
        }

        if ([int]$soakSmoke.TotalNonEmptyDeleteRejections -lt $expectedNonEmptyDeleteRejections) {
            $errors.Add("The soak-smoke artifact reports fewer non-empty-directory delete rejections than expected.")
        }

        if ([int]$soakSmoke.TotalDurableReconnects -lt $expectedDurableReconnects) {
            $errors.Add("The soak-smoke artifact reports fewer durable reconnect completions than expected.")
        }

        if ([int]$soakSmoke.TotalDetachedReadConflicts -lt $expectedDurableReconnects) {
            $errors.Add("The soak-smoke artifact reports fewer detached durable read conflicts than expected.")
        }

        if ([int]$soakSmoke.TotalDetachedLockConflicts -lt $expectedDurableReconnects) {
            $errors.Add("The soak-smoke artifact reports fewer detached durable lock conflicts than expected.")
        }

        if ([int]$soakSmoke.TotalPostReconnectLockSuccesses -lt $expectedDurableReconnects) {
            $errors.Add("The soak-smoke artifact reports fewer post-reconnect competing lock successes than expected.")
        }

        if ([int]$soakSmoke.TotalOplockBreaks -lt $expectedOplockBreaks) {
            $errors.Add("The soak-smoke artifact reports fewer exclusive oplock-break completions than expected.")
        }

        if ([int]$soakSmoke.TotalOplockAcknowledgments -lt $expectedOplockBreaks) {
            $errors.Add("The soak-smoke artifact reports fewer exclusive oplock-break acknowledgments than expected.")
        }

        if ([int]$soakSmoke.TotalLeaseBreaks -lt $expectedLeaseBreaks) {
            $errors.Add("The soak-smoke artifact reports fewer lease-break completions than expected.")
        }

        if ([int]$soakSmoke.TotalLeaseAcknowledgments -lt $expectedLeaseBreaks) {
            $errors.Add("The soak-smoke artifact reports fewer lease-break acknowledgments than expected.")
        }
    }
}

$requiredInteropDialectIds = @("smb2002", "smb21", "smb302")
$dialectAwareArtifactPaths = @(
    "artifacts\real-client-interop\real-client-smoke.json",
    "artifacts\samba-interop\open-cifs-client-to-samba.json",
    "artifacts\samba-interop\sample-server-samba-client.json",
    "artifacts\windows-client-interop\windows-client-smoke.json"
)

for ($artifactIndex = 0; $artifactIndex -lt $dialectAwareArtifactPaths.Length; $artifactIndex++) {
    $artifactPath = Join-Path $repositoryRoot $dialectAwareArtifactPaths[$artifactIndex]

    if (-not (Test-Path $artifactPath)) {
        continue
    }

    try {
        $artifactRuns = Get-ArtifactRuns -Path $artifactPath
    }
    catch {
        $errors.Add("The interop artifact could not be parsed as dialect-matrix JSON: $artifactPath.")
        continue
    }

    $artifactDialectIds = New-Object System.Collections.Generic.List[string]

    for ($runIndex = 0; $runIndex -lt $artifactRuns.Count; $runIndex++) {
        $artifactRun = $artifactRuns[$runIndex]

        try {
            $dialectId = Get-ArtifactRunDialectId -Run $artifactRun
            $artifactDialectIds.Add($dialectId)
        }
        catch {
            $errors.Add("The interop artifact $artifactPath contains a run without a valid dialect identifier.")
            continue
        }

        $artifactFailure = Get-ArtifactRunFailure -Run $artifactRun
        if ($null -ne $artifactFailure) {
            $errors.Add("The interop artifact $artifactPath recorded a failed run for dialect '$dialectId': $artifactFailure")
        }

        if ($artifactPath.EndsWith("windows-client-smoke.json", [System.StringComparison]::OrdinalIgnoreCase) -and $null -eq $artifactRun.mapping) {
            $errors.Add("The Windows interop artifact $artifactPath does not record a mapping snapshot for dialect '$dialectId'.")
        }
    }

    for ($requiredDialectIndex = 0; $requiredDialectIndex -lt $requiredInteropDialectIds.Length; $requiredDialectIndex++) {
        $requiredDialectId = $requiredInteropDialectIds[$requiredDialectIndex]

        if ($artifactDialectIds -notcontains $requiredDialectId) {
            $errors.Add("The interop artifact $artifactPath does not contain a run for required dialect '$requiredDialectId'.")
        }
    }
}

$coverageRows = Get-MarkdownTableRows -Path $coverageMatrixPath -HeaderMarker "| dialect | area | command or capability |" -ExpectedColumnCount 13

for ($coverageIndex = 0; $coverageIndex -lt $coverageRows.Count; $coverageIndex++) {
    $coverageRow = $coverageRows[$coverageIndex]
    $columns = $coverageRow.Columns

    $implementedValue = $false
    if (-not [bool]::TryParse($columns[6], [ref]$implementedValue)) {
        continue
    }

    $implemented = $implementedValue
    if (-not $implemented) {
        continue
    }

    $sambaDate = $columns[10]
    $windowsDate = $columns[11]

    if ($sambaDate -ne "n/a" -and $sambaDate -ne $AsOfDate) {
        $errors.Add("Coverage matrix row $($coverageRow.LineNumber) has stale Samba verification date '$sambaDate'. Expected '$AsOfDate' or 'n/a'.")
    }

    if ($windowsDate -ne "n/a" -and $windowsDate -ne $AsOfDate) {
        $errors.Add("Coverage matrix row $($coverageRow.LineNumber) has stale Windows verification date '$windowsDate'. Expected '$AsOfDate' or 'n/a'.")
    }
}

$interopRows = Get-MarkdownTableRows -Path $interopMatrixPath -HeaderMarker "| role | peer | target environment |" -ExpectedColumnCount 9

for ($interopIndex = 0; $interopIndex -lt $interopRows.Count; $interopIndex++) {
    $interopRow = $interopRows[$interopIndex]
    $columns = $interopRow.Columns
    $smokeStatus = $columns[4]
    $deepStatus = $columns[5]
    $lastVerifiedDate = $columns[6]
    $evidenceEntries = Get-EvidenceEntries -EvidenceColumn $columns[7]
    $rowPassed = $smokeStatus -eq "pass" -or $deepStatus -eq "pass"

    if (-not $rowPassed) {
        continue
    }

    if ($lastVerifiedDate -ne $AsOfDate) {
        $errors.Add("Interop matrix row $($interopRow.LineNumber) has stale last verified date '$lastVerifiedDate'. Expected '$AsOfDate'.")
    }

    if ($evidenceEntries.Length -eq 0) {
        $errors.Add("Interop matrix row $($interopRow.LineNumber) is marked pass but does not list any evidence paths.")
        continue
    }

    for ($evidenceIndex = 0; $evidenceIndex -lt $evidenceEntries.Length; $evidenceIndex++) {
        $evidenceEntry = $evidenceEntries[$evidenceIndex]
        $evidencePath = Join-Path $repositoryRoot $evidenceEntry

        if (-not (Test-Path $evidencePath)) {
            $errors.Add("Interop matrix row $($interopRow.LineNumber) references missing evidence path: $evidencePath.")
            continue
        }

        $validatedEvidencePaths.Add($evidenceEntry)
    }
}

if ($errors.Count -ne 0) {
    for ($errorIndex = 0; $errorIndex -lt $errors.Count; $errorIndex++) {
        Write-Error $errors[$errorIndex]
    }

    exit 1
}

$summary = [pscustomobject]@{
    Configuration = $Configuration
    AsOfDate = $AsOfDate
    CoverageRowsValidated = $coverageRows.Count
    InteropRowsValidated = $interopRows.Count
    RequiredArtifactCount = $requiredArtifactPaths.Length
    ValidatedEvidenceCount = $validatedEvidencePaths.Count
    ValidatedEvidence = $validatedEvidencePaths | Sort-Object -Unique
}

$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $resultPath -Encoding UTF8
Write-Output "Release artifact validation completed. Evidence:"
Write-Output "  $resultPath"

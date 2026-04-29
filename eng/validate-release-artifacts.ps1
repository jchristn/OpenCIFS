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

Invoke-BuildValidator -Command "validate-coverage" -Path $coverageMatrixPath
Invoke-BuildValidator -Command "validate-interop" -Path $interopMatrixPath

$errors = New-Object System.Collections.Generic.List[string]
$validatedEvidencePaths = New-Object System.Collections.Generic.List[string]

$requiredArtifactPaths = @(
    "artifacts\package-smoke\package-metadata.json",
    "artifacts\package-smoke\package-smoke.json",
    "artifacts\readme-smoke\readme-smoke.json",
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

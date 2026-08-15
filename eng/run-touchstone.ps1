param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$ResultsPath = ""
)

$ErrorActionPreference = "Stop"

# The entire OpenCIFS Touchstone suite (Core, Server, Client, and Interop) is now
# exposed through the single consolidated automated runner, OpenCIFS.Test.Automated,
# which executes OpenCIFS.Test.Shared.AllSuites.All.
$project = "src/OpenCIFS.Test.Automated/OpenCIFS.Test.Automated.csproj"

$runArgs = @(
    "run",
    "--project", "$PSScriptRoot\..\$project",
    "--configuration", $Configuration,
    "--framework", $Framework,
    "--no-build"
)

if (-not [string]::IsNullOrWhiteSpace($ResultsPath)) {
    $runArgs += @("--", "--results", $ResultsPath)
}

dotnet @runArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

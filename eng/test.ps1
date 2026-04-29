param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

& "$PSScriptRoot\build.ps1" -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& "$PSScriptRoot\run-touchstone.ps1" -Configuration $Configuration -Framework $Framework
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet test "$PSScriptRoot\..\src\OpenCIFS.sln" --configuration $Configuration --no-build
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& "$PSScriptRoot\run-package-smoke.ps1" -Configuration $Configuration -Framework $Framework
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& "$PSScriptRoot\run-readme-smoke.ps1" -Configuration $Configuration -Framework $Framework
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

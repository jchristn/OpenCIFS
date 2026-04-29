param(
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

dotnet restore "$PSScriptRoot\..\src\OpenCIFS.sln"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet build "$PSScriptRoot\..\src\OpenCIFS.sln" --configuration $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

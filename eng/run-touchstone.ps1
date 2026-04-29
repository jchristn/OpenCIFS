param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

$projects = @(
    "src/OpenCIFS.Core.Tests.Console/OpenCIFS.Core.Tests.Console.csproj",
    "src/OpenCIFS.Server.Tests.Console/OpenCIFS.Server.Tests.Console.csproj",
    "src/OpenCIFS.Client.Tests.Console/OpenCIFS.Client.Tests.Console.csproj",
    "src/OpenCIFS.Interop.Tests.Console/OpenCIFS.Interop.Tests.Console.csproj"
)

foreach ($project in $projects) {
    dotnet run --project "$PSScriptRoot\..\$project" --configuration $Configuration --framework $Framework --no-build
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

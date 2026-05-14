param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$PreviousPackageVersion = "",
    [string]$PreviousClientPackageVersion = "",
    [string]$PreviousServerPackageVersion = "",
    [string]$PackageSource = "",
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

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)

    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-ForConsoleOutput {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedText,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            $content = Get-Content -Path $Path -Raw
            if (-not [string]::IsNullOrEmpty($content) -and $content.Contains($ExpectedText)) {
                return $true
            }
        }

        if ($Process.HasExited) {
            break
        }

        Start-Sleep -Milliseconds 250
    }

    return $false
}

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
            }
        }
        default {
            throw "Unsupported cross-version managed interop dialect '$Dialect'."
        }
    }
}

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Set-Content -Path $Path -Value $Value -Encoding UTF8
}

function Get-FrameworkCsProjText {
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [Parameter(Mandatory = $true)][string]$TargetFramework
    )

    return $Template.Replace("__TARGET_FRAMEWORK__", $TargetFramework)
}

function Get-PackageCsProjText {
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [Parameter(Mandatory = $true)][string]$TargetFramework,
        [Parameter(Mandatory = $true)][string]$PackageVersion
    )

    return $Template.Replace("__TARGET_FRAMEWORK__", $TargetFramework).Replace("__PACKAGE_VERSION__", $PackageVersion)
}

function Initialize-GeneratedProjects {
    param(
        [Parameter(Mandatory = $true)][string]$GeneratedRoot,
        [Parameter(Mandatory = $true)][string]$TargetFramework,
        [Parameter(Mandatory = $true)][string]$PreviousClientVersion,
        [Parameter(Mandatory = $true)][string]$PreviousServerVersion
    )

    $currentClientRoot = Join-Path $GeneratedRoot "current-client"
    $previousClientRoot = Join-Path $GeneratedRoot "previous-client"
    $currentServerRoot = Join-Path $GeneratedRoot "current-server"
    $previousServerRoot = Join-Path $GeneratedRoot "previous-server"

    foreach ($path in @($currentClientRoot, $previousClientRoot, $currentServerRoot, $previousServerRoot)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    $currentClientProjectTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>__TARGET_FRAMEWORK__</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\..\..\src\OpenCIFS.Client\OpenCIFS.Client.csproj" />
    <ProjectReference Include="..\..\..\..\src\OpenCIFS.Protocol\OpenCIFS.Protocol.csproj" />
  </ItemGroup>
</Project>
'@

    $previousClientProjectTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>__TARGET_FRAMEWORK__</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="OpenCIFS.Protocol" Version="__PACKAGE_VERSION__" />
    <PackageReference Include="OpenCIFS.Client" Version="__PACKAGE_VERSION__" />
  </ItemGroup>
</Project>
'@

    $currentServerProjectTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>__TARGET_FRAMEWORK__</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\..\..\src\OpenCIFS.Protocol\OpenCIFS.Protocol.csproj" />
    <ProjectReference Include="..\..\..\..\src\OpenCIFS.Server\OpenCIFS.Server.csproj" />
  </ItemGroup>
</Project>
'@

    $previousServerProjectTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>__TARGET_FRAMEWORK__</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="OpenCIFS.Protocol" Version="__PACKAGE_VERSION__" />
    <PackageReference Include="OpenCIFS.Server" Version="__PACKAGE_VERSION__" />
  </ItemGroup>
</Project>
'@

    $clientProgramTemplate = @'
using System;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using OpenCIFS.Client;
using OpenCIFS.Protocol;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 7)
        {
            Console.Error.WriteLine("Expected arguments: host port dialect shareName userName password summaryPath");
            return 2;
        }

        string host = args[0];
        int port = int.Parse(args[1], CultureInfo.InvariantCulture);
        SmbDialect dialect = (SmbDialect)Enum.Parse(typeof(SmbDialect), args[2], ignoreCase: true);
        string shareName = args[3];
        string userName = args[4];
        string password = args[5];
        string summaryPath = args[6];
        string directoryPath = "/cross-version-" + Guid.NewGuid().ToString("N").Substring(0, 12);
        string filePath = directoryPath + "/hello.txt";
        string renamedPath = directoryPath + "/renamed.txt";
        string expectedText = "Hello from cross-version managed interop " + args[2];

        try
        {
            await using OpenCifsClient client = new OpenCifsClientBuilder()
                .WithServer(host, port)
                .WithDialectRange(dialect, dialect)
                .WithSigningRequired()
                .Build();

            await client.ConnectAsync(new OpenCifsClientCredential
            {
                UserName = userName,
                UserDomain = "WORKGROUP",
                Password = password
            }).ConfigureAwait(false);

            await using OpenCifsShareSession share = await client.OpenShareAsync(shareName).ConfigureAwait(false);
            await share.Directories.CreateAsync(directoryPath).ConfigureAwait(false);

            byte[] payload = Encoding.UTF8.GetBytes(expectedText);
            await share.Files.WriteAllBytesAsync(filePath, payload).ConfigureAwait(false);

            OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync(directoryPath).ConfigureAwait(false);
            byte[] readBytes = await share.Files.ReadAllBytesAsync(filePath).ConfigureAwait(false);
            await share.Files.RenameAsync(filePath, renamedPath).ConfigureAwait(false);
            byte[] renamedBytes = await share.Files.ReadAllBytesAsync(renamedPath).ConfigureAwait(false);
            await share.Files.DeleteAsync(renamedPath).ConfigureAwait(false);
            await share.Directories.DeleteAsync(directoryPath).ConfigureAwait(false);
            await client.DisconnectAsync().ConfigureAwait(false);

            string[] entryNames = entries.Select(static entry => entry.FileName).ToArray();
            if (!entryNames.Any(static fileName => StringComparer.OrdinalIgnoreCase.Equals(fileName, "hello.txt")))
            {
                throw new InvalidOperationException("The cross-version directory enumeration did not return hello.txt.");
            }

            if (!StringComparer.Ordinal.Equals(Encoding.UTF8.GetString(readBytes), expectedText))
            {
                throw new InvalidOperationException("The cross-version file read returned an unexpected payload.");
            }

            if (!StringComparer.Ordinal.Equals(Encoding.UTF8.GetString(renamedBytes), expectedText))
            {
                throw new InvalidOperationException("The cross-version renamed-file read returned an unexpected payload.");
            }

            string? informationalVersion = typeof(OpenCifsClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            object summary = new
            {
                succeeded = true,
                role = "client",
                assembly_name = typeof(OpenCifsClient).Assembly.GetName().Name,
                assembly_version = typeof(OpenCifsClient).Assembly.GetName().Version?.ToString(),
                informational_version = informationalVersion,
                host,
                port,
                dialect = dialect.ToString(),
                share_name = shareName,
                directory_path = directoryPath,
                file_path = filePath,
                renamed_path = renamedPath,
                expected_text = expectedText,
                entry_names = entryNames,
                operations = new[]
                {
                    "negotiate",
                    "session_setup",
                    "tree_connect",
                    "directory_create",
                    "file_write",
                    "directory_enumerate",
                    "file_read",
                    "file_rename",
                    "renamed_file_read",
                    "file_delete",
                    "directory_delete",
                    "tree_disconnect",
                    "session_disconnect"
                },
                failure = (string?)null
            };

            await System.IO.File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            Console.WriteLine("CLIENT_SUCCESS");
            return 0;
        }
        catch (Exception exception)
        {
            string? informationalVersion = typeof(OpenCifsClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            object summary = new
            {
                succeeded = false,
                role = "client",
                assembly_name = typeof(OpenCifsClient).Assembly.GetName().Name,
                assembly_version = typeof(OpenCifsClient).Assembly.GetName().Version?.ToString(),
                informational_version = informationalVersion,
                host,
                port,
                dialect = dialect.ToString(),
                share_name = shareName,
                directory_path = directoryPath,
                file_path = filePath,
                renamed_path = renamedPath,
                failure = exception.ToString()
            };

            await System.IO.File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
    }
}
'@

    $serverProgramTemplate = @'
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Protocol;
using OpenCIFS.Server;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 9)
        {
            Console.Error.WriteLine("Expected arguments: port dialect shareRoot shareName userName password stopSignalPath summaryPath serverLabel");
            return 2;
        }

        int port = int.Parse(args[0], CultureInfo.InvariantCulture);
        SmbDialect dialect = (SmbDialect)Enum.Parse(typeof(SmbDialect), args[1], ignoreCase: true);
        string shareRoot = args[2];
        string shareName = args[3];
        string userName = args[4];
        string password = args[5];
        string stopSignalPath = args[6];
        string summaryPath = args[7];
        string serverLabel = args[8];

        Directory.CreateDirectory(shareRoot);

        await using OpenCifsServerApplication server = new OpenCifsServerBuilder()
            .WithServerName("127.0.0.1")
            .WithBindAddress("127.0.0.1")
            .WithBindPort(port)
            .WithDialectRange(dialect, dialect)
            .WithSigningRequired()
            .AddAccount(new OpenCifsServerAccount
            {
                UserName = userName,
                UserDomain = "WORKGROUP",
                Password = password
            })
            .AddShare(shareName, share => share.UseLocalFileSystem(shareRoot))
            .BuildApplication();

        try
        {
            await server.StartAsync(CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine("SERVER_READY");
            Console.Out.Flush();

            while (!File.Exists(stopSignalPath))
            {
                await Task.Delay(200).ConfigureAwait(false);
            }

            string[] availableShares = server.GetAvailableShares().Select(static share => share.ShareName).ToArray();
            string? informationalVersion = typeof(OpenCifsServerBuilder).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            object summary = new
            {
                succeeded = true,
                role = "server",
                server_label = serverLabel,
                assembly_name = typeof(OpenCifsServerBuilder).Assembly.GetName().Name,
                assembly_version = typeof(OpenCifsServerBuilder).Assembly.GetName().Version?.ToString(),
                informational_version = informationalVersion,
                port,
                dialect = dialect.ToString(),
                share_root = shareRoot,
                share_name = shareName,
                available_shares = availableShares,
                failure = (string?)null
            };

            await server.StopAsync(CancellationToken.None).ConfigureAwait(false);
            await File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            return 0;
        }
        catch (Exception exception)
        {
            string? informationalVersion = typeof(OpenCifsServerBuilder).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            object summary = new
            {
                succeeded = false,
                role = "server",
                server_label = serverLabel,
                assembly_name = typeof(OpenCifsServerBuilder).Assembly.GetName().Name,
                assembly_version = typeof(OpenCifsServerBuilder).Assembly.GetName().Version?.ToString(),
                informational_version = informationalVersion,
                port,
                dialect = dialect.ToString(),
                share_root = shareRoot,
                share_name = shareName,
                failure = exception.ToString()
            };

            await File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
    }
}
'@

    Write-TextFile -Path (Join-Path $currentClientRoot "CurrentClientInterop.csproj") -Value (Get-FrameworkCsProjText -Template $currentClientProjectTemplate -TargetFramework $TargetFramework)
    Write-TextFile -Path (Join-Path $currentClientRoot "Program.cs") -Value $clientProgramTemplate

    Write-TextFile -Path (Join-Path $previousClientRoot "PreviousClientInterop.csproj") -Value (Get-PackageCsProjText -Template $previousClientProjectTemplate -TargetFramework $TargetFramework -PackageVersion $PreviousClientVersion)
    Write-TextFile -Path (Join-Path $previousClientRoot "Program.cs") -Value $clientProgramTemplate

    Write-TextFile -Path (Join-Path $currentServerRoot "CurrentServerInterop.csproj") -Value (Get-FrameworkCsProjText -Template $currentServerProjectTemplate -TargetFramework $TargetFramework)
    Write-TextFile -Path (Join-Path $currentServerRoot "Program.cs") -Value $serverProgramTemplate

    Write-TextFile -Path (Join-Path $previousServerRoot "PreviousServerInterop.csproj") -Value (Get-PackageCsProjText -Template $previousServerProjectTemplate -TargetFramework $TargetFramework -PackageVersion $PreviousServerVersion)
    Write-TextFile -Path (Join-Path $previousServerRoot "Program.cs") -Value $serverProgramTemplate

    return [pscustomobject]@{
        CurrentClientProjectPath = Join-Path $currentClientRoot "CurrentClientInterop.csproj"
        PreviousClientProjectPath = Join-Path $previousClientRoot "PreviousClientInterop.csproj"
        CurrentServerProjectPath = Join-Path $currentServerRoot "CurrentServerInterop.csproj"
        PreviousServerProjectPath = Join-Path $previousServerRoot "PreviousServerInterop.csproj"
    }
}

function Write-NuGetConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PrimarySource
    )

    $sources = New-Object System.Collections.Generic.List[string]
    $sources.Add($PrimarySource)

    $defaultSource = "https://api.nuget.org/v3/index.json"
    if (-not [string]::Equals($PrimarySource.TrimEnd('\'), $defaultSource.TrimEnd('/'), [System.StringComparison]::OrdinalIgnoreCase)) {
        $sources.Add($defaultSource)
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('<?xml version="1.0" encoding="utf-8"?>')
    $lines.Add('<configuration>')
    $lines.Add('  <packageSources>')
    $lines.Add('    <clear />')

    for ($index = 0; $index -lt $sources.Count; $index++) {
        $sourceName = "source{0}" -f ($index + 1)
        $sourceValue = [System.Security.SecurityElement]::Escape($sources[$index])
        $lines.Add('    <add key="' + $sourceName + '" value="' + $sourceValue + '" />')
    }

    $lines.Add('  </packageSources>')
    $lines.Add('</configuration>')

    Set-Content -Path $Path -Value $lines -Encoding UTF8
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ErrorMessage
    )

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $ErrorMessage
    }
}

function Build-InteropProjects {
    param(
        [Parameter(Mandatory = $true)]$Projects,
        [Parameter(Mandatory = $true)][string]$NuGetConfigPath,
        [Parameter(Mandatory = $true)][string]$PackageCacheRoot,
        [Parameter(Mandatory = $true)][string]$Configuration,
        [Parameter(Mandatory = $true)][string]$Framework
    )

    $projectPaths = @(
        $Projects.CurrentClientProjectPath,
        $Projects.PreviousClientProjectPath,
        $Projects.CurrentServerProjectPath,
        $Projects.PreviousServerProjectPath
    )

    foreach ($projectPath in $projectPaths) {
        Invoke-DotNet -Arguments @(
            "restore", $projectPath,
            "--configfile", $NuGetConfigPath,
            "--packages", $PackageCacheRoot
        ) -ErrorMessage ("Failed to restore cross-version interop project '" + $projectPath + "'.")

        Invoke-DotNet -Arguments @(
            "build", $projectPath,
            "--configuration", $Configuration,
            "--framework", $Framework,
            "--no-restore"
        ) -ErrorMessage ("Failed to build cross-version interop project '" + $projectPath + "'.")
    }
}

function Get-RunSummaryDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label summary was not produced: $Path."
    }

    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Invoke-CrossVersionTopology {
    param(
        [Parameter(Mandatory = $true)][string]$TopologyId,
        [Parameter(Mandatory = $true)][string]$PeerTopology,
        [Parameter(Mandatory = $true)][string]$ClientProjectPath,
        [Parameter(Mandatory = $true)][string]$ServerProjectPath,
        [Parameter(Mandatory = $true)][string]$ServerLabel,
        [Parameter(Mandatory = $true)][string[]]$Dialects,
        [Parameter(Mandatory = $true)][string]$Configuration,
        [Parameter(Mandatory = $true)][string]$Framework,
        [Parameter(Mandatory = $true)][string]$ArtifactRoot
    )

    $runs = New-Object System.Collections.Generic.List[object]
    $shareName = "public"
    $userName = "tester"
    $password = "Password123!"

    foreach ($dialect in $Dialects) {
        $dialectMetadata = Get-DialectMetadata -Dialect $dialect
        $runRoot = Join-Path $ArtifactRoot $TopologyId
        $runRoot = Join-Path $runRoot $dialectMetadata.DialectId
        $shareRoot = Join-Path $runRoot "share"
        $stopSignalPath = Join-Path $runRoot "server.stop"
        $serverSummaryPath = Join-Path $runRoot "server-summary.json"
        $clientSummaryPath = Join-Path $runRoot "client-summary.json"
        $serverOutputPath = Join-Path $runRoot "server-output.txt"
        $serverErrorPath = Join-Path $runRoot "server-error.txt"
        $clientOutputPath = Join-Path $runRoot "client-output.txt"
        $clientErrorPath = Join-Path $runRoot "client-error.txt"
        $port = Get-FreeTcpPort

        New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null

        $serverArguments = @(
            "run",
            "--project", $ServerProjectPath,
            "--configuration", $Configuration,
            "--framework", $Framework,
            "--no-build",
            "--",
            $port.ToString([System.Globalization.CultureInfo]::InvariantCulture),
            $dialectMetadata.Dialect,
            $shareRoot,
            $shareName,
            $userName,
            $password,
            $stopSignalPath,
            $serverSummaryPath,
            $ServerLabel
        )

        $clientArguments = @(
            "run",
            "--project", $ClientProjectPath,
            "--configuration", $Configuration,
            "--framework", $Framework,
            "--no-build",
            "--",
            "127.0.0.1",
            $port.ToString([System.Globalization.CultureInfo]::InvariantCulture),
            $dialectMetadata.Dialect,
            $shareName,
            $userName,
            $password,
            $clientSummaryPath
        )

        $serverProcess = $null
        $clientProcess = $null

        try {
            $serverProcess = Start-Process `
                -FilePath "dotnet" `
                -ArgumentList $serverArguments `
                -WorkingDirectory $repositoryRoot `
                -RedirectStandardOutput $serverOutputPath `
                -RedirectStandardError $serverErrorPath `
                -WindowStyle Hidden `
                -PassThru

            $serverReady = Wait-ForConsoleOutput -Process $serverProcess -Path $serverOutputPath -ExpectedText "SERVER_READY" -TimeoutSeconds 60
            if (-not $serverReady) {
                throw "The cross-version server process did not report readiness for $TopologyId / $($dialectMetadata.DialectId)."
            }

            $clientProcess = Start-Process `
                -FilePath "dotnet" `
                -ArgumentList $clientArguments `
                -WorkingDirectory $repositoryRoot `
                -RedirectStandardOutput $clientOutputPath `
                -RedirectStandardError $clientErrorPath `
                -WindowStyle Hidden `
                -PassThru `
                -Wait

            New-Item -ItemType File -Path $stopSignalPath -Force | Out-Null

            if (-not $serverProcess.WaitForExit(30000)) {
                throw "The cross-version server process did not stop in time for $TopologyId / $($dialectMetadata.DialectId)."
            }

            $clientSummary = Get-RunSummaryDocument -Path $clientSummaryPath -Label ("Client " + $TopologyId + " " + $dialectMetadata.DialectId)
            $serverSummary = Get-RunSummaryDocument -Path $serverSummaryPath -Label ("Server " + $TopologyId + " " + $dialectMetadata.DialectId)

            if ([int]$clientProcess.ExitCode -ne 0) {
                throw "The cross-version client process exited with code $($clientProcess.ExitCode) for $TopologyId / $($dialectMetadata.DialectId)."
            }

            if ([int]$serverProcess.ExitCode -ne 0) {
                throw "The cross-version server process exited with code $($serverProcess.ExitCode) for $TopologyId / $($dialectMetadata.DialectId)."
            }

            if (-not [bool]$clientSummary.succeeded) {
                throw "The cross-version client summary recorded failure for $TopologyId / $($dialectMetadata.DialectId): $($clientSummary.failure)"
            }

            if (-not [bool]$serverSummary.succeeded) {
                throw "The cross-version server summary recorded failure for $TopologyId / $($dialectMetadata.DialectId): $($serverSummary.failure)"
            }

            $runs.Add([pscustomobject]@{
                topology_id = $TopologyId
                peer_topology = $PeerTopology
                dialect = $dialectMetadata.Dialect
                dialect_id = $dialectMetadata.DialectId
                label = $dialectMetadata.Label
                final_state = [pscustomobject]@{
                    failure = $null
                }
                client_summary = $clientSummary
                server_summary = $serverSummary
                client_summary_path = $clientSummaryPath
                server_summary_path = $serverSummaryPath
                client_output_path = $clientOutputPath
                client_error_path = $clientErrorPath
                server_output_path = $serverOutputPath
                server_error_path = $serverErrorPath
                share_root = $shareRoot
            })
        }
        catch {
            $failure = $_.Exception.Message
            $clientSummary = $null
            $serverSummary = $null

            if (Test-Path -LiteralPath $clientSummaryPath) {
                $clientSummary = Get-Content -Path $clientSummaryPath -Raw | ConvertFrom-Json
            }

            if (Test-Path -LiteralPath $serverSummaryPath) {
                $serverSummary = Get-Content -Path $serverSummaryPath -Raw | ConvertFrom-Json
            }

            $runs.Add([pscustomobject]@{
                topology_id = $TopologyId
                peer_topology = $PeerTopology
                dialect = $dialectMetadata.Dialect
                dialect_id = $dialectMetadata.DialectId
                label = $dialectMetadata.Label
                final_state = [pscustomobject]@{
                    failure = $failure
                }
                client_summary = $clientSummary
                server_summary = $serverSummary
                client_summary_path = $clientSummaryPath
                server_summary_path = $serverSummaryPath
                client_output_path = $clientOutputPath
                client_error_path = $clientErrorPath
                server_output_path = $serverOutputPath
                server_error_path = $serverErrorPath
                share_root = $shareRoot
            })

            break
        }
        finally {
            if (-not (Test-Path -LiteralPath $stopSignalPath)) {
                New-Item -ItemType File -Path $stopSignalPath -Force | Out-Null
            }

            if ($null -ne $clientProcess -and -not $clientProcess.HasExited) {
                try {
                    $clientProcess.Kill()
                }
                catch {
                }
            }

            if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
                try {
                    $serverProcess.Kill()
                }
                catch {
                }
            }
        }
    }

    return $runs
}

$sharedPackageVersion = Get-ConfiguredValue -ParameterValue $PreviousPackageVersion -EnvironmentVariableName "OPENCIFS_CROSS_VERSION_PACKAGE_VERSION"

if ([string]::IsNullOrWhiteSpace($PreviousClientPackageVersion)) {
    $PreviousClientPackageVersion = $sharedPackageVersion
}

if ([string]::IsNullOrWhiteSpace($PreviousServerPackageVersion)) {
    $PreviousServerPackageVersion = $sharedPackageVersion
}

$PreviousClientPackageVersion = Get-RequiredConfiguredValue -ParameterValue $PreviousClientPackageVersion -ParameterName "PreviousClientPackageVersion" -EnvironmentVariableName "OPENCIFS_PREVIOUS_CLIENT_PACKAGE_VERSION"
$PreviousServerPackageVersion = Get-RequiredConfiguredValue -ParameterValue $PreviousServerPackageVersion -ParameterName "PreviousServerPackageVersion" -EnvironmentVariableName "OPENCIFS_PREVIOUS_SERVER_PACKAGE_VERSION"
$PackageSource = Get-ConfiguredValue -ParameterValue $PackageSource -EnvironmentVariableName "OPENCIFS_CROSS_VERSION_PACKAGE_SOURCE"

if ([string]::IsNullOrWhiteSpace($PackageSource)) {
    $PackageSource = "https://api.nuget.org/v3/index.json"
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\cross-version-managed-interop"
$generatedRoot = Join-Path $artifactRoot "generated"
$packageCacheRoot = Join-Path $artifactRoot "packages"
$nuGetConfigPath = Join-Path $artifactRoot "NuGet.Config"
$resultPath = Join-Path $artifactRoot "cross-version-managed-interop.json"
$currentRevision = ""

try {
    $currentRevision = ((& git -C $repositoryRoot rev-parse HEAD 2>$null) | Select-Object -First 1).Trim()
}
catch {
    $currentRevision = ""
}

if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null
New-Item -ItemType Directory -Path $packageCacheRoot -Force | Out-Null

$projects = Initialize-GeneratedProjects `
    -GeneratedRoot $generatedRoot `
    -TargetFramework $Framework `
    -PreviousClientVersion $PreviousClientPackageVersion `
    -PreviousServerVersion $PreviousServerPackageVersion

Write-NuGetConfig -Path $nuGetConfigPath -PrimarySource $PackageSource
Build-InteropProjects `
    -Projects $projects `
    -NuGetConfigPath $nuGetConfigPath `
    -PackageCacheRoot $packageCacheRoot `
    -Configuration $Configuration `
    -Framework $Framework

$topologies = New-Object System.Collections.Generic.List[object]

$currentClientPreviousServerRuns = Invoke-CrossVersionTopology `
    -TopologyId "current-client_vs_previous-server" `
    -PeerTopology "Current OpenCIFS.Client source build -> previous released OpenCIFS.Server package" `
    -ClientProjectPath $projects.CurrentClientProjectPath `
    -ServerProjectPath $projects.PreviousServerProjectPath `
    -ServerLabel "previous-server-package" `
    -Dialects $Dialects `
    -Configuration $Configuration `
    -Framework $Framework `
    -ArtifactRoot $artifactRoot

$topologies.Add([pscustomobject]@{
    topology_id = "current-client_vs_previous-server"
    peer_topology = "Current OpenCIFS.Client source build -> previous released OpenCIFS.Server package"
    current_role = "client"
    previous_package_id = "OpenCIFS.Server"
    previous_package_version = $PreviousServerPackageVersion
    runs = $currentClientPreviousServerRuns
})

$previousClientCurrentServerRuns = Invoke-CrossVersionTopology `
    -TopologyId "previous-client_vs_current-server" `
    -PeerTopology "Previous released OpenCIFS.Client package -> current OpenCIFS.Server source build" `
    -ClientProjectPath $projects.PreviousClientProjectPath `
    -ServerProjectPath $projects.CurrentServerProjectPath `
    -ServerLabel "current-server-source" `
    -Dialects $Dialects `
    -Configuration $Configuration `
    -Framework $Framework `
    -ArtifactRoot $artifactRoot

$topologies.Add([pscustomobject]@{
    topology_id = "previous-client_vs_current-server"
    peer_topology = "Previous released OpenCIFS.Client package -> current OpenCIFS.Server source build"
    current_role = "server"
    previous_package_id = "OpenCIFS.Client"
    previous_package_version = $PreviousClientPackageVersion
    runs = $previousClientCurrentServerRuns
})

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    configuration = $Configuration
    framework = $Framework
    current_revision = $currentRevision
    package_source = $PackageSource
    previous_client_package_version = $PreviousClientPackageVersion
    previous_server_package_version = $PreviousServerPackageVersion
    nuget_config_path = $nuGetConfigPath
    generated_projects = $projects
    topologies = $topologies
} | ConvertTo-Json -Depth 10 | Set-Content -Path $resultPath -Encoding UTF8

$failures = @(
    $topologies |
        ForEach-Object { @($_.runs) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.final_state.failure) }
)

if ($failures.Count -ne 0) {
    throw "Cross-version managed interop recorded one or more failed runs. See $resultPath."
}

Write-Output "Cross-version managed interop completed."
Write-Output "  $resultPath"

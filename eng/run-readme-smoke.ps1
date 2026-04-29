param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0"
)

$ErrorActionPreference = "Stop"

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\readme-smoke"
$projectRoot = Join-Path $artifactRoot "consumer"
$projectPath = Join-Path $projectRoot "ReadmeSmokeApp.csproj"
$programPath = Join-Path $projectRoot "Program.cs"
$resultPath = Join-Path $artifactRoot "readme-smoke.json"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null

$protocolProjectPath = (Join-Path $repositoryRoot "src\OpenCIFS.Protocol\OpenCIFS.Protocol.csproj")
$clientProjectPath = (Join-Path $repositoryRoot "src\OpenCIFS.Client\OpenCIFS.Client.csproj")
$serverProjectPath = (Join-Path $repositoryRoot "src\OpenCIFS.Server\OpenCIFS.Server.csproj")

$projectContent = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$Framework</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="$protocolProjectPath" />
    <ProjectReference Include="$clientProjectPath" />
    <ProjectReference Include="$serverProjectPath" />
  </ItemGroup>
</Project>
"@

Set-Content -Path $projectPath -Value $projectContent -Encoding UTF8

$programContent = @"
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Client;
using OpenCIFS.Protocol;
using OpenCIFS.Server;

internal static class Program
{
    private static async Task<int> Main()
    {
        string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsReadmeSmoke_" + Guid.NewGuid().ToString("N"));
        string shareRoot = Path.Combine(rootPath, "DemoShare");
        Directory.CreateDirectory(shareRoot);
        await File.WriteAllTextAsync(Path.Combine(shareRoot, "welcome.txt"), "hello from OpenCIFS").ConfigureAwait(false);

        int port = AllocateLoopbackPort();
        int authenticatedSessionCount = 0;
        int treeConnectCount = 0;
        int createCount = 0;
        bool deleteFailureObserved = false;
        string roundTripText;
        ulong endOfFile;

        SmbDialect minimumDialect = SmbDialect.Smb2002;
        SmbDialect maximumDialect = SmbDialect.Smb21;

        OpenCifsServerOptions serverOptions = new OpenCifsServerOptions
        {
            ServerName = "127.0.0.1",
            BindAddress = "127.0.0.1",
            BindPort = port,
            MinimumDialect = minimumDialect,
            MaximumDialect = maximumDialect
        };

        OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(serverOptions)
            .AddAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            })
            .AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = "share",
                RootPath = shareRoot,
                CreateRootIfMissing = true
            })
            .ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
            {
                AuthenticatedSessionCallback = context =>
                {
                    authenticatedSessionCount++;
                    return null;
                },
                TreeConnectCallback = context =>
                {
                    treeConnectCount++;
                    return null;
                },
                CreateCallback = context =>
                {
                    createCount++;
                    return null;
                }
            });

        await using OpenCifsServerApplication server = builder.BuildApplication(
            exception => Console.Error.WriteLine("[readme-smoke-server] " + exception.Message));

        OpenCifsClientOptions clientOptions = new OpenCifsClientOptions
        {
            ServerName = "127.0.0.1",
            ServerPort = port,
            MinimumDialect = minimumDialect,
            MaximumDialect = maximumDialect
        };

        OpenCifsClientCredential credential = new OpenCifsClientCredential
        {
            UserName = "alice",
            UserDomain = "WORKGROUP",
            Password = "Password123!"
        };

        try
        {
            await server.StartAsync(CancellationToken.None).ConfigureAwait(false);

            await using OpenCifsClientFacade client = new OpenCifsClientFacade(clientOptions);
            await client.ConnectAsync(credential).ConfigureAwait(false);
            await client.EchoAsync().ConfigureAwait(false);

            await client.CreateDirectoryAsync("share", "docs").ConfigureAwait(false);
            await client.WriteAllBytesAsync("share", "docs\\hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS")).ConfigureAwait(false);

            byte[] fileBytes = await client.ReadAllBytesAsync("share", "docs\\hello.txt").ConfigureAwait(false);
            OpenCifsClientFileMetadata metadata = await client.GetMetadataAsync("share", "docs\\hello.txt").ConfigureAwait(false);
            OpenCifsClientDirectoryEntry[] entries = await client.EnumerateDirectoryAsync("share", "docs").ConfigureAwait(false);

            roundTripText = Encoding.UTF8.GetString(fileBytes);
            endOfFile = metadata.EndOfFile;

            try
            {
                await client.DeleteAsync("share", "docs").ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
            {
                deleteFailureObserved = true;
            }

            await client.RenameAsync("share", "docs\\hello.txt", "docs\\hello-renamed.txt").ConfigureAwait(false);
            await client.DeleteAsync("share", "docs\\hello-renamed.txt").ConfigureAwait(false);
            await client.DeleteAsync("share", "docs").ConfigureAwait(false);

            if (!deleteFailureObserved)
            {
                throw new InvalidOperationException("README smoke did not observe the documented non-empty-directory delete rejection path.");
            }

            if (!StringComparer.Ordinal.Equals(roundTripText, "hello from OpenCIFS"))
            {
                throw new InvalidOperationException("README smoke round-trip payload did not match the documented example payload.");
            }

            if (endOfFile != 19UL)
            {
                throw new InvalidOperationException("README smoke metadata end-of-file value did not match the documented example payload length.");
            }

            if (!entries.Any(static entry => StringComparer.OrdinalIgnoreCase.Equals(entry.FileName, "hello.txt")))
            {
                throw new InvalidOperationException("README smoke directory enumeration did not return hello.txt.");
            }

            if (authenticatedSessionCount <= 0 || treeConnectCount <= 0 || createCount <= 0)
            {
                throw new InvalidOperationException("README smoke did not exercise the documented callback surface.");
            }

            Console.WriteLine(JsonSerializer.Serialize(new
            {
                MinimumDialect = minimumDialect.ToString(),
                MaximumDialect = maximumDialect.ToString(),
                Port = port,
                RoundTripText = roundTripText,
                EndOfFile = endOfFile,
                EnumeratedFileCount = entries.Length,
                AuthenticatedSessionCount = authenticatedSessionCount,
                TreeConnectCount = treeConnectCount,
                CreateCount = createCount,
                DeleteFailureObserved = deleteFailureObserved
            }, new JsonSerializerOptions
            {
                WriteIndented = true
            }));

            return 0;
        }
        finally
        {
            try
            {
                await server.StopAsync().ConfigureAwait(false);
            }
            catch
            {
            }

            try
            {
                if (Directory.Exists(rootPath))
                {
                    Directory.Delete(rootPath, recursive: true);
                }
            }
            catch
            {
            }
        }
    }

    private static int AllocateLoopbackPort()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);

        try
        {
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }
}
"@

Set-Content -Path $programPath -Value $programContent -Encoding UTF8

dotnet restore $projectPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet build $projectPath --configuration $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet run --project $projectPath --configuration $Configuration --no-build --no-restore | Tee-Object -FilePath $resultPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "README smoke completed. Evidence:"
Write-Host "  $resultPath"

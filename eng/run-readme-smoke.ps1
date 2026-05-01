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
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
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
        string configuredShareName;
        string applicationShareName;

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

        OpenCifsServerBuilder builder = new OpenCifsServerBuilder(serverOptions)
            .AddAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            })
            .AddShare("share", share => share.UseLocalFileSystem(shareRoot))
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

        OpenCifsServerShareInfo[] configuredShares = builder.GetAvailableShares().ToArray();
        if (configuredShares.Length != 1 || !StringComparer.Ordinal.Equals(configuredShares[0].ShareName, "share"))
        {
            throw new InvalidOperationException("README smoke builder share introspection did not expose the documented share registration.");
        }

        configuredShareName = configuredShares[0].ShareName;

        OpenCifsServer configuredServer = builder.Build();
        if (!StringComparer.Ordinal.Equals(configuredServer.Settings.ServerName, "127.0.0.1"))
        {
            throw new InvalidOperationException("README smoke configured-server surface did not preserve the documented server name.");
        }

        OpenCifsServerShareInfo[] serverShares = configuredServer.GetAvailableShares().ToArray();
        if (serverShares.Length != 1 || !StringComparer.Ordinal.Equals(serverShares[0].ShareName, "share"))
        {
            throw new InvalidOperationException("README smoke configured-server share introspection did not expose the documented share registration.");
        }

        await using OpenCifsServerApplication server = configuredServer.BuildApplication(
            exception => Console.Error.WriteLine("[readme-smoke-server] " + exception.Message));

        OpenCifsServerShareInfo[] applicationShares = server.GetAvailableShares().ToArray();
        if (applicationShares.Length != 1 || !StringComparer.Ordinal.Equals(applicationShares[0].ShareName, "share"))
        {
            throw new InvalidOperationException("README smoke application share introspection did not expose the documented share registration.");
        }

        applicationShareName = applicationShares[0].ShareName;

        OpenCifsClientCredential credential = new OpenCifsClientCredential
        {
            UserName = "alice",
            UserDomain = "WORKGROUP",
            Password = "Password123!"
        };

        try
        {
            await server.StartAsync(CancellationToken.None).ConfigureAwait(false);

            await using OpenCifsClient client = new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", port)
                .WithDialectRange(minimumDialect, maximumDialect)
                .Build();
            await client.ConnectAsync(credential).ConfigureAwait(false);
            await client.EchoAsync().ConfigureAwait(false);

            await using OpenCifsShareSession share = await client.OpenShareAsync("share").ConfigureAwait(false);
            await share.Directories.CreateAsync("/docs").ConfigureAwait(false);
            await share.Files.WriteAllBytesAsync("/docs/hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS")).ConfigureAwait(false);

            byte[] fileBytes = await share.Files.ReadAllBytesAsync("/docs/hello.txt").ConfigureAwait(false);
            OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/hello.txt").ConfigureAwait(false);
            OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("/docs").ConfigureAwait(false);

            roundTripText = Encoding.UTF8.GetString(fileBytes);
            endOfFile = metadata.EndOfFile;

            try
            {
                await share.Directories.DeleteAsync("/docs").ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
            {
                deleteFailureObserved = true;
            }

            await share.Files.RenameAsync("/docs/hello.txt", "/docs/hello-renamed.txt").ConfigureAwait(false);
            await share.Files.DeleteAsync("/docs/hello-renamed.txt").ConfigureAwait(false);
            await share.Directories.DeleteAsync("/docs").ConfigureAwait(false);
            await client.DisconnectAsync().ConfigureAwait(false);

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
                ConfiguredShareName = configuredShareName,
                ApplicationShareName = applicationShareName,
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

dotnet run --project $projectPath --configuration $Configuration --framework $Framework --no-build --no-restore | Tee-Object -FilePath $resultPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "README smoke completed. Evidence:"
Write-Host "  $resultPath"

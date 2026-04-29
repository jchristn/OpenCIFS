param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$PackageVersion = "1.0.0-package-smoke"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\package-smoke"
$feedRoot = Join-Path $artifactRoot "feed"
$consumerRoot = Join-Path $artifactRoot "consumer"
$consumerProjectPath = Join-Path $consumerRoot "PackageSmokeApp.csproj"
$consumerProgramPath = Join-Path $consumerRoot "Program.cs"
$nuGetConfigPath = Join-Path $consumerRoot "NuGet.Config"
$metadataPath = Join-Path $artifactRoot "package-metadata.json"
$resultPath = Join-Path $artifactRoot "package-smoke.json"

function Get-ArchiveEntryNames {
    param(
        [string]$PackagePath
    )

    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)

    try {
        return @($archive.Entries | ForEach-Object { $_.FullName })
    }
    finally {
        $archive.Dispose()
    }
}

function Get-ArchiveEntryText {
    param(
        [string]$PackagePath,
        [string]$EntryName
    )

    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)

    try {
        $entry = $archive.Entries | Where-Object { $_.FullName -eq $EntryName } | Select-Object -First 1
        if ($null -eq $entry) {
            return $null
        }

        $reader = [System.IO.StreamReader]::new($entry.Open())

        try {
            return $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-NuspecNodeText {
    param(
        [System.Xml.XmlNode]$ParentNode,
        [string]$ChildName
    )

    $childNode = $ParentNode.SelectSingleNode("*[local-name()='$ChildName']")
    if ($null -eq $childNode) {
        return $null
    }

    return $childNode.InnerText
}

function Assert-PackageArtifact {
    param(
        [string]$PackagePath,
        [string]$PackageId,
        [string]$ExpectedReadmeFile,
        [string]$RequiredReadmePhrase
    )

    $entryNames = Get-ArchiveEntryNames -PackagePath $PackagePath
    $requiredEntries = @(
        $ExpectedReadmeFile,
        "LICENSE.md",
        "lib/net8.0/$PackageId.dll",
        "lib/net8.0/$PackageId.xml",
        "lib/net10.0/$PackageId.dll",
        "lib/net10.0/$PackageId.xml"
    )

    foreach ($requiredEntry in $requiredEntries) {
        if ($entryNames -notcontains $requiredEntry) {
            throw "Package '$PackageId' is missing required entry '$requiredEntry'."
        }
    }

    $nuspecEntryName = $entryNames | Where-Object { $_ -like "*.nuspec" } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($nuspecEntryName)) {
        throw "Package '$PackageId' is missing a nuspec entry."
    }

    [xml]$nuspecDocument = Get-ArchiveEntryText -PackagePath $PackagePath -EntryName $nuspecEntryName
    $metadataNode = $nuspecDocument.SelectSingleNode("/*[local-name()='package']/*[local-name()='metadata']")
    if ($null -eq $metadataNode) {
        throw "Package '$PackageId' nuspec metadata could not be read."
    }

    $packageIdentity = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "id"
    $authors = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "authors"
    $description = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "description"
    $readme = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "readme"
    $projectUrl = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "projectUrl"
    $tags = Get-NuspecNodeText -ParentNode $metadataNode -ChildName "tags"

    if (-not [string]::Equals($packageIdentity, $PackageId, [System.StringComparison]::Ordinal)) {
        throw "Package '$PackageId' emitted nuspec id '$packageIdentity'."
    }

    if ([string]::IsNullOrWhiteSpace($authors)) {
        throw "Package '$PackageId' is missing package authors metadata."
    }

    if ([string]::IsNullOrWhiteSpace($description)) {
        throw "Package '$PackageId' is missing a package description."
    }

    if (-not [string]::Equals($readme, $ExpectedReadmeFile, [System.StringComparison]::Ordinal)) {
        throw "Package '$PackageId' emitted readme '$readme' instead of '$ExpectedReadmeFile'."
    }

    if ([string]::IsNullOrWhiteSpace($projectUrl)) {
        throw "Package '$PackageId' is missing a project URL."
    }

    if ([string]::IsNullOrWhiteSpace($tags)) {
        throw "Package '$PackageId' is missing package tags."
    }

    $licenseNode = $metadataNode.SelectSingleNode("*[local-name()='license']")
    if ($null -eq $licenseNode -or -not [string]::Equals($licenseNode.InnerText, "MIT", [System.StringComparison]::Ordinal)) {
        throw "Package '$PackageId' is missing the expected MIT license expression."
    }

    $repositoryNode = $metadataNode.SelectSingleNode("*[local-name()='repository']")
    if ($null -eq $repositoryNode) {
        throw "Package '$PackageId' is missing repository metadata."
    }

    $repositoryUrl = $repositoryNode.GetAttribute("url")
    $repositoryType = $repositoryNode.GetAttribute("type")
    if ([string]::IsNullOrWhiteSpace($repositoryUrl)) {
        throw "Package '$PackageId' repository metadata is missing the repository URL."
    }

    if (-not [string]::Equals($repositoryType, "git", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Package '$PackageId' repository metadata is missing the expected git repository type."
    }

    $readmeText = Get-ArchiveEntryText -PackagePath $PackagePath -EntryName $ExpectedReadmeFile
    if (-not $readmeText.StartsWith("# $PackageId", [System.StringComparison]::Ordinal)) {
        throw "Package '$PackageId' readme does not start with the expected package heading."
    }

    if ($readmeText.IndexOf($RequiredReadmePhrase, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Package '$PackageId' readme does not contain the expected phrase '$RequiredReadmePhrase'."
    }

    $dependencyIds = @(
        $metadataNode.SelectNodes("*[local-name()='dependencies']/*[local-name()='group']/*[local-name()='dependency']") |
            ForEach-Object { $_.GetAttribute("id") } |
            Sort-Object -Unique
    )

    return [pscustomobject]@{
        PackageId = $PackageId
        PackagePath = $PackagePath
        ReadmeFile = $ExpectedReadmeFile
        Tags = $tags
        Dependencies = $dependencyIds
    }
}

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $feedRoot -Force | Out-Null
New-Item -ItemType Directory -Path $consumerRoot -Force | Out-Null

$packageDefinitions = @(
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Protocol/OpenCIFS.Protocol.csproj"
        PackageId = "OpenCIFS.Protocol"
        ReadmeFile = "PackageReadme.md"
        RequiredReadmePhrase = "SmbDialect"
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Security/OpenCIFS.Security.csproj"
        PackageId = "OpenCIFS.Security"
        ReadmeFile = "PackageReadme.md"
        RequiredReadmePhrase = "NTLMv2"
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Transport/OpenCIFS.Transport.csproj"
        PackageId = "OpenCIFS.Transport"
        ReadmeFile = "PackageReadme.md"
        RequiredReadmePhrase = "direct-TCP"
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Client/OpenCIFS.Client.csproj"
        PackageId = "OpenCIFS.Client"
        ReadmeFile = "PackageReadme.md"
        RequiredReadmePhrase = "OpenCifsClientFacade"
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Server/OpenCIFS.Server.csproj"
        PackageId = "OpenCIFS.Server"
        ReadmeFile = "PackageReadme.md"
        RequiredReadmePhrase = "OpenCifsServerHostBuilder"
    }
)

$packageMetadata = [System.Collections.Generic.List[object]]::new()

foreach ($definition in $packageDefinitions) {
    dotnet pack (Join-Path $repositoryRoot $definition.ProjectPath) `
        --configuration $Configuration `
        --output $feedRoot `
        -p:PackageVersion=$PackageVersion

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $packagePath = Join-Path $feedRoot "$($definition.PackageId).$PackageVersion.nupkg"
    $packageMetadata.Add((Assert-PackageArtifact `
        -PackagePath $packagePath `
        -PackageId $definition.PackageId `
        -ExpectedReadmeFile $definition.ReadmeFile `
        -RequiredReadmePhrase $definition.RequiredReadmePhrase))
}

$packageMetadata | ConvertTo-Json -Depth 6 | Set-Content -Path $metadataPath -Encoding UTF8

$consumerProject = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$Framework</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="OpenCIFS.Protocol" Version="$PackageVersion" />
    <PackageReference Include="OpenCIFS.Client" Version="$PackageVersion" />
    <PackageReference Include="OpenCIFS.Server" Version="$PackageVersion" />
  </ItemGroup>
</Project>
"@

Set-Content -Path $consumerProjectPath -Value $consumerProject -Encoding UTF8

$nuGetConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-package-smoke" value="$feedRoot" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"@

Set-Content -Path $nuGetConfigPath -Value $nuGetConfig -Encoding UTF8

$consumerProgram = @"
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
        string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsPackageSmoke_" + Guid.NewGuid().ToString("N"));
        string shareRoot = Path.Combine(rootPath, "share");
        Directory.CreateDirectory(shareRoot);

        int port = AllocateLoopbackPort();
        OpenCifsServerOptions serverOptions = new OpenCifsServerOptions
        {
            ServerName = "127.0.0.1",
            BindAddress = "127.0.0.1",
            BindPort = port,
            MinimumDialect = SmbDialect.Smb2002,
            MaximumDialect = SmbDialect.Smb21,
            ShareName = "share",
            SharePath = shareRoot
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
            });

        await using OpenCifsServerApplication server = builder.BuildApplication(
            exception => Console.Error.WriteLine("[package-smoke-server] " + exception));

        OpenCifsClientOptions clientOptions = new OpenCifsClientOptions
        {
            ServerName = "127.0.0.1",
            ServerPort = port,
            MinimumDialect = SmbDialect.Smb2002,
            MaximumDialect = SmbDialect.Smb21,
            RequireSigning = true
        };

        bool badCredentialRejected = false;
        bool nonEmptyDirectoryDeleteRejected = false;
        string roundTripText;
        ulong endOfFile;

        try
        {
            await server.StartAsync(CancellationToken.None);

            await using (OpenCifsClientFacade invalidClient = new OpenCifsClientFacade(clientOptions))
            {
                try
                {
                    await invalidClient.ConnectAsync(new OpenCifsClientCredential
                    {
                        UserName = "alice",
                        UserDomain = "WORKGROUP",
                        Password = "WrongPassword!"
                    }).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.AccessDenied)
                {
                    badCredentialRejected = true;
                }
            }

            await using OpenCifsClientFacade client = new OpenCifsClientFacade(clientOptions);
            await client.ConnectAsync(new OpenCifsClientCredential
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            }).ConfigureAwait(false);

            await client.EchoAsync().ConfigureAwait(false);
            await client.CreateDirectoryAsync("share", "docs").ConfigureAwait(false);

            byte[] payload = Encoding.UTF8.GetBytes("hello from package smoke");
            await client.WriteAllBytesAsync("share", @"docs\smoke.txt", payload).ConfigureAwait(false);

            try
            {
                await client.DeleteAsync("share", "docs").ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
            {
                nonEmptyDirectoryDeleteRejected = true;
            }

            byte[] readBytes = await client.ReadAllBytesAsync("share", @"docs\smoke.txt").ConfigureAwait(false);
            roundTripText = Encoding.UTF8.GetString(readBytes);

            OpenCifsClientFileMetadata metadata = await client.GetMetadataAsync("share", @"docs\smoke.txt").ConfigureAwait(false);
            endOfFile = metadata.EndOfFile;

            OpenCifsClientDirectoryEntry[] directoryEntries = await client.EnumerateDirectoryAsync("share", "docs").ConfigureAwait(false);

            if (!directoryEntries.Any(static entry => StringComparer.OrdinalIgnoreCase.Equals(entry.FileName, "smoke.txt")))
            {
                throw new InvalidOperationException("The package smoke directory enumeration did not return smoke.txt.");
            }

            await client.RenameAsync("share", @"docs\smoke.txt", @"docs\renamed.txt").ConfigureAwait(false);
            await client.DeleteAsync("share", @"docs\renamed.txt").ConfigureAwait(false);
            await client.DeleteAsync("share", "docs").ConfigureAwait(false);

            if (!badCredentialRejected)
            {
                throw new InvalidOperationException("The package smoke flow did not reject invalid credentials.");
            }

            if (!nonEmptyDirectoryDeleteRejected)
            {
                throw new InvalidOperationException("The package smoke flow did not reject a non-empty directory delete.");
            }

            if (!StringComparer.Ordinal.Equals(roundTripText, "hello from package smoke"))
            {
                throw new InvalidOperationException("The package smoke file round trip returned an unexpected payload.");
            }

            if (endOfFile != checked((ulong)payload.Length))
            {
                throw new InvalidOperationException("The package smoke metadata query returned an unexpected end-of-file value.");
            }

            Console.WriteLine(JsonSerializer.Serialize(new
            {
                PackageVersion = "$PackageVersion",
                DialectFloor = SmbDialect.Smb2002.ToString(),
                DialectCeiling = SmbDialect.Smb21.ToString(),
                Port = port,
                BadCredentialRejected = badCredentialRejected,
                NonEmptyDirectoryDeleteRejected = nonEmptyDirectoryDeleteRejected,
                EndOfFile = endOfFile,
                RoundTripText = roundTripText
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

Set-Content -Path $consumerProgramPath -Value $consumerProgram -Encoding UTF8

dotnet restore $consumerProjectPath --configfile $nuGetConfigPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet build $consumerProjectPath --configuration $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet run --project $consumerProjectPath --configuration $Configuration --no-build --no-restore | Tee-Object -FilePath $resultPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Package smoke completed. Evidence:"
Write-Host "  $metadataPath"
Write-Host "  $resultPath"

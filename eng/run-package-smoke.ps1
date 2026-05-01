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
$packageCacheRoot = Join-Path $artifactRoot "packages"
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
        [string]$ExpectedDescription,
        [string[]]$RequiredReadmePhrases
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

    if (-not [string]::Equals($description, $ExpectedDescription, [System.StringComparison]::Ordinal)) {
        throw "Package '$PackageId' emitted description '$description' instead of '$ExpectedDescription'."
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

    foreach ($requiredReadmePhrase in $RequiredReadmePhrases) {
        if ($readmeText.IndexOf($requiredReadmePhrase, [System.StringComparison]::Ordinal) -lt 0) {
            throw "Package '$PackageId' readme does not contain the expected phrase '$requiredReadmePhrase'."
        }
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
        Description = $description
        Tags = $tags
        Dependencies = $dependencyIds
    }
}

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

if ($PackageVersion -eq "1.0.0-package-smoke") {
    $PackageVersion = "1.0.0-package-smoke.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
}

New-Item -ItemType Directory -Path $feedRoot -Force | Out-Null
New-Item -ItemType Directory -Path $packageCacheRoot -Force | Out-Null
New-Item -ItemType Directory -Path $consumerRoot -Force | Out-Null

$packageDefinitions = @(
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Protocol/OpenCIFS.Protocol.csproj"
        PackageId = "OpenCIFS.Protocol"
        ReadmeFile = "PackageReadme.md"
        ExpectedDescription = "Shared OpenCIFS SMB/CIFS protocol models, codecs, and wire-format foundations."
        RequiredReadmePhrases = @(
            "SmbDialect",
            '`OpenCIFS.Protocol` is not a standalone SMB client or server.',
            "SMB 3.x and SMB1/CIFS compatibility work beyond the current bounded scope remains backlog."
        )
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Security/OpenCIFS.Security.csproj"
        PackageId = "OpenCIFS.Security"
        ReadmeFile = "PackageReadme.md"
        ExpectedDescription = "Shared OpenCIFS NTLMv2, SPNEGO, signing, encryption, and key-derivation helpers."
        RequiredReadmePhrases = @(
            "NTLMv2",
            '`OpenCIFS.Security` is an advanced dependency package.',
            "Native Kerberos and broader SMB 3.x behavior such as SMB 3.1.1 signing or encryption negotiation remain backlog."
        )
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Transport/OpenCIFS.Transport.csproj"
        PackageId = "OpenCIFS.Transport"
        ReadmeFile = "PackageReadme.md"
        ExpectedDescription = "Shared OpenCIFS direct-TCP, NetBIOS session-service, and framing helpers."
        RequiredReadmePhrases = @(
            "direct-TCP",
            '`OpenCIFS.Transport` is an advanced dependency package.',
            "managed SMB 2.0.2 and SMB 2.1 client and server flows"
        )
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Client/OpenCIFS.Client.csproj"
        PackageId = "OpenCIFS.Client"
        ReadmeFile = "PackageReadme.md"
        ExpectedDescription = "Managed OpenCIFS direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 client library."
        RequiredReadmePhrases = @(
            "OpenCifsClientBuilder",
            "Managed direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 client surface for OpenCIFS.",
            'bounded remote share browsing and share inspection over `IPC$` and `srvsvc`, plus bounded generic named-pipe transceive over `IPC$`, when the target server exposes those paths',
            "bounded SMB 3.0 / SMB 3.0.2 secure-negotiate validation",
            "SMB 3.1.1, Kerberos, and broader Windows-server interop remain backlog."
        )
    },
    [pscustomobject]@{
        ProjectPath = "src/OpenCIFS.Server/OpenCIFS.Server.csproj"
        PackageId = "OpenCIFS.Server"
        ReadmeFile = "PackageReadme.md"
        ExpectedDescription = "Managed OpenCIFS direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 server library."
        RequiredReadmePhrases = @(
            "OpenCifsServerBuilder",
            'bounded local `IPC$` / named-pipe hosting with the built-in `srvsvc` share-enumeration/share-info endpoint, the built-in UTF-8 echo endpoint, plus host-provided named-pipe endpoints',
            "bounded SMB 3.0 / SMB 3.0.2 negotiate, secure-negotiate validation, AES-CMAC signing, and SMB 3.0.2 AES-128-CCM session encryption",
            "Continuous availability, persistent clustered handles, SMB 3.1.1, SMB1/CIFS, DFS, broader named-pipe semantics, and Kerberos remain backlog."
        )
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
        -ExpectedDescription $definition.ExpectedDescription `
        -RequiredReadmePhrases $definition.RequiredReadmePhrases))
}

$packageMetadata | ConvertTo-Json -Depth 6 | Set-Content -Path $metadataPath -Encoding UTF8

$consumerProject = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
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

        OpenCifsServerBuilder builder = new OpenCifsServerBuilder(serverOptions)
            .AddAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            })
            .AddShare("share", share => share.UseLocalFileSystem(shareRoot));

        await using OpenCifsServerApplication server = builder.BuildApplication(
            exception => Console.Error.WriteLine("[package-smoke-server] " + exception));

        bool badCredentialRejected = false;
        bool nonEmptyDirectoryDeleteRejected = false;
        string roundTripText;
        ulong endOfFile;
        string configuredShareName;
        string applicationShareName;

        try
        {
            OpenCifsServerShareInfo[] configuredShares = builder.GetAvailableShares().ToArray();
            if (configuredShares.Length != 1 || !StringComparer.Ordinal.Equals(configuredShares[0].ShareName, "share"))
            {
                throw new InvalidOperationException("The package smoke builder share introspection did not expose the configured share.");
            }

            configuredShareName = configuredShares[0].ShareName;

            OpenCifsServerShareInfo[] applicationShares = server.GetAvailableShares().ToArray();
            if (applicationShares.Length != 1 || !StringComparer.Ordinal.Equals(applicationShares[0].ShareName, "share"))
            {
                throw new InvalidOperationException("The package smoke application share introspection did not expose the configured share.");
            }

            applicationShareName = applicationShares[0].ShareName;

            await server.StartAsync(CancellationToken.None);

            await using (OpenCifsClient invalidClient = new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", port)
                .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                .WithSigningRequired()
                .Build())
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

            await using OpenCifsClient client = new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", port)
                .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                .WithSigningRequired()
                .Build();
            await client.ConnectAsync(new OpenCifsClientCredential
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            }).ConfigureAwait(false);

            await client.EchoAsync().ConfigureAwait(false);
            await using OpenCifsShareSession share = await client.OpenShareAsync("share").ConfigureAwait(false);
            await share.Directories.CreateAsync("/docs").ConfigureAwait(false);

            byte[] payload = Encoding.UTF8.GetBytes("hello from package smoke");
            await share.Files.WriteAllBytesAsync("/docs/smoke.txt", payload).ConfigureAwait(false);

            try
            {
                await share.Directories.DeleteAsync("/docs").ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
            {
                nonEmptyDirectoryDeleteRejected = true;
            }

            byte[] readBytes = await share.Files.ReadAllBytesAsync("/docs/smoke.txt").ConfigureAwait(false);
            roundTripText = Encoding.UTF8.GetString(readBytes);

            OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/smoke.txt").ConfigureAwait(false);
            endOfFile = metadata.EndOfFile;

            OpenCifsClientDirectoryEntry[] directoryEntries = await share.Directories.EnumerateAsync("/docs").ConfigureAwait(false);

            if (!directoryEntries.Any(static entry => StringComparer.OrdinalIgnoreCase.Equals(entry.FileName, "smoke.txt")))
            {
                throw new InvalidOperationException("The package smoke directory enumeration did not return smoke.txt.");
            }

            await share.Files.RenameAsync("/docs/smoke.txt", "/docs/renamed.txt").ConfigureAwait(false);
            await share.Files.DeleteAsync("/docs/renamed.txt").ConfigureAwait(false);
            await share.Directories.DeleteAsync("/docs").ConfigureAwait(false);
            await client.DisconnectAsync().ConfigureAwait(false);

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
                ConfiguredShareName = configuredShareName,
                ApplicationShareName = applicationShareName,
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

dotnet restore $consumerProjectPath --configfile $nuGetConfigPath --packages $packageCacheRoot
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet build $consumerProjectPath --configuration $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

dotnet run --project $consumerProjectPath --configuration $Configuration --framework $Framework --no-build --no-restore | Tee-Object -FilePath $resultPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Package smoke completed. Evidence:"
Write-Host "  $metadataPath"
Write-Host "  $resultPath"

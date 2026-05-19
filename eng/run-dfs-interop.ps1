param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$ServerName = "",
    [string]$ShareName = "",
    [string]$NamespacePath = "",
    [string]$UserName = "",
    [string]$Password = "",
    [string]$Domain = "",
    [string]$PeerLabel = "",
    [int]$Port = 0,
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

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Set-Content -Path $Path -Value $Value -Encoding UTF8
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

function Get-DialectMetadata {
    param([string]$Dialect)

    switch ($Dialect) {
        "Smb2002" {
            return [pscustomobject]@{
                Dialect = "Smb2002"
                DialectId = "smb2002"
                Label = "SMB 2.0.2"
                PreferEncryption = $false
                EnableSmb311Preview = $false
            }
        }
        "Smb21" {
            return [pscustomobject]@{
                Dialect = "Smb21"
                DialectId = "smb21"
                Label = "SMB 2.1"
                PreferEncryption = $false
                EnableSmb311Preview = $false
            }
        }
        "Smb302" {
            return [pscustomobject]@{
                Dialect = "Smb302"
                DialectId = "smb302"
                Label = "SMB 3.0.2"
                PreferEncryption = $true
                EnableSmb311Preview = $false
            }
        }
        "Smb311" {
            return [pscustomobject]@{
                Dialect = "Smb311"
                DialectId = "smb311"
                Label = "SMB 3.1.1"
                PreferEncryption = $true
                EnableSmb311Preview = $true
            }
        }
        default {
            throw "Unsupported DFS interop dialect '$Dialect'."
        }
    }
}

function Initialize-GeneratedHarnessProject {
    param(
        [Parameter(Mandatory = $true)][string]$GeneratedRoot,
        [Parameter(Mandatory = $true)][string]$TargetFramework
    )

    New-Item -ItemType Directory -Path $GeneratedRoot -Force | Out-Null

    $projectTemplate = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>__TARGET_FRAMEWORK__</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\..\src\OpenCIFS.Client\OpenCIFS.Client.csproj" />
    <ProjectReference Include="..\..\..\src\OpenCIFS.Protocol\OpenCIFS.Protocol.csproj" />
  </ItemGroup>
</Project>
'@

    $programTemplate = @'
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
        if (args.Length != 10)
        {
            Console.Error.WriteLine("Expected arguments: serverName port shareName namespacePath userName password domain dialect summaryPath peerLabel");
            return 2;
        }

        string serverName = args[0];
        int port = int.Parse(args[1], CultureInfo.InvariantCulture);
        string shareName = args[2];
        string namespacePath = NormalizeRelativePath(args[3]);
        string userName = args[4];
        string password = args[5];
        string domain = args[6];
        SmbDialect dialect = (SmbDialect)Enum.Parse(typeof(SmbDialect), args[7], ignoreCase: true);
        string summaryPath = args[8];
        string peerLabel = args[9];
        string uniqueId = "opencifs-dfs-" + Guid.NewGuid().ToString("N").Substring(0, 12);
        string expectedText = "Hello from OpenCIFS DFS interop " + args[7];
        string relativeDirectoryPath = CombineRelativePath(namespacePath, uniqueId);
        string filePath = CombineRelativePath(relativeDirectoryPath, "hello.txt");
        string renamedFilePath = CombineRelativePath(relativeDirectoryPath, "renamed.txt");

        try
        {
            OpenCifsClientBuilder namespaceClientBuilder = new OpenCifsClientBuilder()
                .WithServer(serverName, port)
                .WithDialectRange(dialect, dialect)
                .WithSigningRequired()
                .WithPreferredEncryption(dialect >= SmbDialect.Smb30);

            if (dialect == SmbDialect.Smb311)
            {
                namespaceClientBuilder.WithSmb311Preview();
            }

            OpenCifsResolvedDfsPath firstResolution;
            OpenCifsResolvedDfsPath secondResolution;
            OpenCifsDfsReferral[] referrals;

            await using (OpenCifsClient namespaceClient = namespaceClientBuilder.Build())
            {
                await namespaceClient.ConnectAsync(new OpenCifsClientCredential
                {
                    UserName = userName,
                    UserDomain = domain,
                    Password = password
                }).ConfigureAwait(false);

                await using (OpenCifsShareSession namespaceShare = await namespaceClient.OpenShareAsync(shareName).ConfigureAwait(false))
                {
                    referrals = await namespaceShare.GetDfsReferralsAsync(namespacePath).ConfigureAwait(false);

                    if (referrals.Length == 0)
                    {
                        throw new InvalidOperationException("The DFS namespace query did not return any referrals.");
                    }

                    firstResolution = await namespaceShare.ResolvePathAsync(namespacePath).ConfigureAwait(false);
                    secondResolution = await namespaceShare.ResolvePathAsync(namespacePath).ConfigureAwait(false);
                }

                await namespaceClient.DisconnectAsync().ConfigureAwait(false);
            }

            if (!secondResolution.WasResolvedFromCache)
            {
                throw new InvalidOperationException("The second DFS resolution did not report cache reuse.");
            }

            if (!StringComparer.OrdinalIgnoreCase.Equals(firstResolution.TargetUncPath, secondResolution.TargetUncPath))
            {
                throw new InvalidOperationException("The cached DFS resolution did not preserve the same target UNC path.");
            }

            bool redirectedServerChanged = !StringComparer.OrdinalIgnoreCase.Equals(firstResolution.TargetServerName, serverName);
            bool redirectedShareChanged = !StringComparer.OrdinalIgnoreCase.Equals(firstResolution.TargetShareName, shareName);
            if (!redirectedServerChanged && !redirectedShareChanged)
            {
                throw new InvalidOperationException("The DFS resolution did not produce a redirected storage target.");
            }

            byte[] payload = Encoding.UTF8.GetBytes(expectedText);
            string targetDirectoryPath = CombineRelativePath(firstResolution.TargetRelativePath, uniqueId);
            string targetFilePath = CombineRelativePath(targetDirectoryPath, "hello.txt");
            string targetRenamedFilePath = CombineRelativePath(targetDirectoryPath, "renamed.txt");
            string[] entryNames;
            byte[] readBytes;
            byte[] renamedBytes;

            OpenCifsClientBuilder targetClientBuilder = new OpenCifsClientBuilder()
                .WithServer(firstResolution.TargetServerName, port)
                .WithDialectRange(dialect, dialect)
                .WithSigningRequired()
                .WithPreferredEncryption(dialect >= SmbDialect.Smb30);

            if (dialect == SmbDialect.Smb311)
            {
                targetClientBuilder.WithSmb311Preview();
            }

            await using (OpenCifsClient targetClient = targetClientBuilder.Build())
            {
                await targetClient.ConnectAsync(new OpenCifsClientCredential
                {
                    UserName = userName,
                    UserDomain = domain,
                    Password = password
                }).ConfigureAwait(false);

                await using (OpenCifsShareSession targetShare = await targetClient.OpenShareAsync(firstResolution.TargetShareName).ConfigureAwait(false))
                {
                    await targetShare.Directories.CreateAsync(targetDirectoryPath).ConfigureAwait(false);
                    await targetShare.Files.WriteAllBytesAsync(targetFilePath, payload).ConfigureAwait(false);
                    entryNames = (await targetShare.Directories.EnumerateAsync(targetDirectoryPath).ConfigureAwait(false))
                        .Select(static entry => entry.FileName)
                        .ToArray();
                    readBytes = await targetShare.Files.ReadAllBytesAsync(targetFilePath).ConfigureAwait(false);
                    await targetShare.Files.RenameAsync(targetFilePath, targetRenamedFilePath).ConfigureAwait(false);
                    renamedBytes = await targetShare.Files.ReadAllBytesAsync(targetRenamedFilePath).ConfigureAwait(false);
                    await targetShare.Files.DeleteAsync(targetRenamedFilePath).ConfigureAwait(false);
                    await targetShare.Directories.DeleteAsync(targetDirectoryPath).ConfigureAwait(false);
                }

                await targetClient.DisconnectAsync().ConfigureAwait(false);
            }

            if (!entryNames.Any(static fileName => StringComparer.OrdinalIgnoreCase.Equals(fileName, "hello.txt")))
            {
                throw new InvalidOperationException("The DFS target directory enumeration did not include hello.txt.");
            }

            if (!StringComparer.Ordinal.Equals(Encoding.UTF8.GetString(readBytes), expectedText))
            {
                throw new InvalidOperationException("The DFS target file read returned an unexpected payload.");
            }

            if (!StringComparer.Ordinal.Equals(Encoding.UTF8.GetString(renamedBytes), expectedText))
            {
                throw new InvalidOperationException("The DFS target renamed-file read returned an unexpected payload.");
            }

            string? informationalVersion = typeof(OpenCifsClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            object summary = new
            {
                succeeded = true,
                peer_label = peerLabel,
                namespace_server_name = serverName,
                namespace_share_name = shareName,
                namespace_path = namespacePath,
                target_operation_directory = targetDirectoryPath,
                assembly_name = typeof(OpenCifsClient).Assembly.GetName().Name,
                assembly_version = typeof(OpenCifsClient).Assembly.GetName().Version?.ToString(),
                informational_version = informationalVersion,
                dialect = dialect.ToString(),
                port,
                redirected_server_changed = redirectedServerChanged,
                redirected_share_changed = redirectedShareChanged,
                referrals = referrals.Select(ProjectReferral).ToArray(),
                initial_resolution = ProjectResolution(firstResolution),
                cached_resolution = ProjectResolution(secondResolution),
                relative_directory_path = relativeDirectoryPath,
                file_path = filePath,
                renamed_file_path = renamedFilePath,
                target_file_path = targetFilePath,
                target_renamed_file_path = targetRenamedFilePath,
                entry_names = entryNames,
                expected_text = expectedText,
                operations = new[]
                {
                    "dfs_get_referrals",
                    "dfs_resolve_first",
                    "dfs_resolve_repeat_cached",
                    "redirected_tree_connect",
                    "redirected_directory_create",
                    "redirected_file_write",
                    "redirected_directory_enumerate",
                    "redirected_file_read",
                    "redirected_file_rename",
                    "redirected_renamed_file_read",
                    "redirected_file_delete",
                    "redirected_directory_delete"
                },
                failure = (string?)null
            };

            await System.IO.File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            Console.WriteLine("DFS_INTEROP_SUCCESS");
            return 0;
        }
        catch (Exception exception)
        {
            object summary = new
            {
                succeeded = false,
                namespace_server_name = serverName,
                namespace_share_name = shareName,
                namespace_path = namespacePath,
                dialect = dialect.ToString(),
                port,
                peer_label = peerLabel,
                failure = exception.ToString()
            };

            await System.IO.File.WriteAllTextAsync(
                summaryPath,
                JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);

            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
    }

    private static object ProjectReferral(OpenCifsDfsReferral referral)
    {
        return new
        {
            requested_path = referral.RequestedPath,
            referral_path = referral.ReferralPath,
            network_address = referral.NetworkAddress,
            target_server_name = referral.TargetServerName,
            target_share_name = referral.TargetShareName,
            target_path = referral.TargetPath,
            path_consumed = referral.PathConsumed,
            time_to_live_seconds = referral.TimeToLiveSeconds,
            expires_at_utc = referral.ExpiresAtUtc.ToString("o", CultureInfo.InvariantCulture),
            is_root_target = referral.IsRootTarget
        };
    }

    private static object ProjectResolution(OpenCifsResolvedDfsPath resolution)
    {
        return new
        {
            original_path = resolution.OriginalPath,
            referral_path = resolution.ReferralPath,
            target_server_name = resolution.TargetServerName,
            target_share_name = resolution.TargetShareName,
            target_relative_path = resolution.TargetRelativePath,
            target_unc_path = resolution.TargetUncPath,
            expires_at_utc = resolution.ExpiresAtUtc.ToString("o", CultureInfo.InvariantCulture),
            was_resolved_from_cache = resolution.WasResolvedFromCache,
            is_same_server = resolution.IsSameServer
        };
    }

    private static string NormalizeRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentNullException(nameof(path), "The DFS namespace path cannot be null or whitespace.");
        }

        return path.Trim().Replace('/', '\\').Trim('\\');
    }

    private static string CombineRelativePath(string left, string right)
    {
        string normalizedLeft = string.IsNullOrWhiteSpace(left) ? string.Empty : NormalizeRelativePath(left);
        string normalizedRight = string.IsNullOrWhiteSpace(right) ? string.Empty : NormalizeRelativePath(right);

        if (normalizedLeft.Length == 0)
        {
            return normalizedRight;
        }

        if (normalizedRight.Length == 0)
        {
            return normalizedLeft;
        }

        return normalizedLeft + "\\" + normalizedRight;
    }
}
'@

    $projectText = $projectTemplate.Replace("__TARGET_FRAMEWORK__", $TargetFramework)
    $projectPath = Join-Path $GeneratedRoot "DfsInteropHarness.csproj"
    $programPath = Join-Path $GeneratedRoot "Program.cs"

    Write-TextFile -Path $projectPath -Value $projectText
    Write-TextFile -Path $programPath -Value $programTemplate

    return $projectPath
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

function Invoke-DfsInteropRun {
    param(
        [Parameter(Mandatory = $true)]$DialectMetadata,
        [Parameter(Mandatory = $true)][string]$ProjectPath
    )

    $runRoot = Join-Path $artifactRoot $DialectMetadata.DialectId
    $summaryPath = Join-Path $runRoot "dfs-summary.json"
    $clientOutputPath = Join-Path $runRoot "dfs-client-output.txt"
    $clientErrorPath = Join-Path $runRoot "dfs-client-error.txt"

    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

    $clientArguments = @(
        "run",
        "--project", $ProjectPath,
        "--configuration", $Configuration,
        "--framework", $Framework,
        "--no-build",
        "--",
        $ServerName,
        $Port.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        $ShareName,
        $NamespacePath,
        $UserName,
        $Password,
        $Domain,
        $DialectMetadata.Dialect,
        $summaryPath,
        $PeerLabel
    )

    $runFailure = $null
    $summary = $null

    try {
        $clientProcess = Start-Process `
            -FilePath "dotnet" `
            -ArgumentList $clientArguments `
            -WorkingDirectory $repositoryRoot `
            -RedirectStandardOutput $clientOutputPath `
            -RedirectStandardError $clientErrorPath `
            -WindowStyle Hidden `
            -PassThru `
            -Wait

        $summary = Get-RunSummaryDocument -Path $summaryPath -Label ("DFS interop " + $DialectMetadata.DialectId)

        if ([int]$clientProcess.ExitCode -ne 0) {
            $runFailure = "The DFS interop client process exited with code $($clientProcess.ExitCode) for $($DialectMetadata.DialectId)."
        }
        elseif (-not [bool]$summary.succeeded) {
            $runFailure = [string]$summary.failure
        }
    }
    catch {
        $runFailure = $_.Exception.Message

        if (Test-Path -LiteralPath $summaryPath) {
            $summary = Get-Content -Path $summaryPath -Raw | ConvertFrom-Json
        }
    }

    return [pscustomobject]@{
        dialect = $DialectMetadata.Dialect
        dialect_id = $DialectMetadata.DialectId
        label = $DialectMetadata.Label
        peer_label = $PeerLabel
        namespace_server_name = $ServerName
        namespace_share_name = $ShareName
        namespace_path = $NamespacePath
        port = $Port
        prefer_encryption = [bool]$DialectMetadata.PreferEncryption
        final_state = [pscustomobject]@{
            failure = $runFailure
        }
        summary = $summary
        summary_path = $summaryPath
        client_output_path = $clientOutputPath
        client_error_path = $clientErrorPath
    }
}

$ServerName = Get-RequiredConfiguredValue -ParameterValue $ServerName -ParameterName "ServerName" -EnvironmentVariableName "OPENCIFS_DFS_SERVER_NAME"
$ShareName = Get-RequiredConfiguredValue -ParameterValue $ShareName -ParameterName "ShareName" -EnvironmentVariableName "OPENCIFS_DFS_SHARE_NAME"
$NamespacePath = Get-RequiredConfiguredValue -ParameterValue $NamespacePath -ParameterName "NamespacePath" -EnvironmentVariableName "OPENCIFS_DFS_NAMESPACE_PATH"
$UserName = Get-RequiredConfiguredValue -ParameterValue $UserName -ParameterName "UserName" -EnvironmentVariableName "OPENCIFS_DFS_USER_NAME"
$Password = Get-RequiredConfiguredValue -ParameterValue $Password -ParameterName "Password" -EnvironmentVariableName "OPENCIFS_DFS_PASSWORD"
$Domain = Get-ConfiguredValue -ParameterValue $Domain -EnvironmentVariableName "OPENCIFS_DFS_DOMAIN"
$PeerLabel = Get-ConfiguredValue -ParameterValue $PeerLabel -EnvironmentVariableName "OPENCIFS_DFS_PEER_LABEL"

if ([string]::IsNullOrWhiteSpace($PeerLabel)) {
    $PeerLabel = $ServerName
}

if ($Port -le 0) {
    $environmentPort = [Environment]::GetEnvironmentVariable("OPENCIFS_DFS_PORT")
    if ([string]::IsNullOrWhiteSpace($environmentPort)) {
        $Port = 445
    }
    else {
        $parsedPort = 0
        if (-not [int]::TryParse($environmentPort, [ref]$parsedPort) -or $parsedPort -le 0) {
            throw "OPENCIFS_DFS_PORT must be a positive integer when supplied."
        }

        $Port = $parsedPort
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\dfs-interop"
$generatedRoot = Join-Path $artifactRoot "generated"
$resultPath = Join-Path $artifactRoot "dfs-interop.json"
$environmentPath = Join-Path $artifactRoot "dfs-environment.json"

if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null

$projectPath = Initialize-GeneratedHarnessProject -GeneratedRoot $generatedRoot -TargetFramework $Framework

[pscustomobject]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    client_machine = $env:COMPUTERNAME
    os_version = [System.Environment]::OSVersion.VersionString
    namespace_server_name = $ServerName
    namespace_share_name = $ShareName
    namespace_path = $NamespacePath
    peer_label = $PeerLabel
    port = $Port
    domain_supplied = -not [string]::IsNullOrWhiteSpace($Domain)
    dialects = $Dialects
} | ConvertTo-Json -Depth 4 | Set-Content -Path $environmentPath -Encoding UTF8

Invoke-DotNet -Arguments @(
    "restore", $projectPath
) -ErrorMessage "Failed to restore the DFS interop harness project."

Invoke-DotNet -Arguments @(
    "build", $projectPath,
    "--configuration", $Configuration,
    "--framework", $Framework,
    "--no-restore"
) -ErrorMessage "Failed to build the DFS interop harness project."

$runs = New-Object System.Collections.Generic.List[object]

foreach ($dialect in $Dialects) {
    $metadata = Get-DialectMetadata -Dialect $dialect
    $run = Invoke-DfsInteropRun -DialectMetadata $metadata -ProjectPath $projectPath
    $runs.Add($run)

    if (-not [string]::IsNullOrWhiteSpace([string]$run.final_state.failure)) {
        [pscustomobject]@{
            configuration = $Configuration
            framework = $Framework
            peer_topology = "OpenCIFS.Client -> external DFS namespace"
            environment_path = $environmentPath
            generated_project_path = $projectPath
            runs = $runs
        } | ConvertTo-Json -Depth 10 | Set-Content -Path $resultPath -Encoding UTF8
        throw "DFS interop failed for $($metadata.DialectId): $($run.final_state.failure)"
    }
}

[pscustomobject]@{
    configuration = $Configuration
    framework = $Framework
    peer_topology = "OpenCIFS.Client -> external DFS namespace"
    environment_path = $environmentPath
    generated_project_path = $projectPath
    runs = $runs
} | ConvertTo-Json -Depth 10 | Set-Content -Path $resultPath -Encoding UTF8

Write-Output "DFS interop completed."
Write-Output "  $resultPath"
Write-Output "  $environmentPath"

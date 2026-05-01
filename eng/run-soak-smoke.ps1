param(
    [string]$Configuration = "Release",
    [string]$Framework = "net8.0",
    [int]$WorkerCount = 4,
    [int]$WorkerIterations = 3,
    [int]$DurableIterations = 3,
    [int]$OplockIterations = 3,
    [int]$LeaseIterations = 3,
    [int]$MinimumDurationSeconds = 45,
    [int]$LargePayloadLength = 200000
)

$ErrorActionPreference = "Stop"

if ($WorkerCount -lt 1) {
    throw "WorkerCount must be at least 1."
}

if ($WorkerIterations -lt 1) {
    throw "WorkerIterations must be at least 1."
}

if ($DurableIterations -lt 1) {
    throw "DurableIterations must be at least 1."
}

if ($OplockIterations -lt 1) {
    throw "OplockIterations must be at least 1."
}

if ($LeaseIterations -lt 1) {
    throw "LeaseIterations must be at least 1."
}

if ($MinimumDurationSeconds -lt 1) {
    throw "MinimumDurationSeconds must be at least 1."
}

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the soak run exercises the bounded large-I/O path."
}

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$artifactRoot = Join-Path $repositoryRoot "artifacts\soak-smoke"
$projectRoot = Join-Path $artifactRoot "consumer"
$projectPath = Join-Path $projectRoot "SoakSmokeApp.csproj"
$programPath = Join-Path $projectRoot "Program.cs"
$resultPath = Join-Path $artifactRoot "soak-smoke.json"

if (Test-Path $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null

$protocolProjectPath = Join-Path $repositoryRoot "src\OpenCIFS.Protocol\OpenCIFS.Protocol.csproj"
$clientProjectPath = Join-Path $repositoryRoot "src\OpenCIFS.Client\OpenCIFS.Client.csproj"
$serverProjectPath = Join-Path $repositoryRoot "src\OpenCIFS.Server\OpenCIFS.Server.csproj"

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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Client;
using OpenCIFS.Protocol;
using OpenCIFS.Server;

internal static class Program
{
    private const string ShareName = "share";
    private const string UserName = "alice";
    private const string UserDomain = "WORKGROUP";
    private const string Password = "Password123!";
    private const uint GenericReadAccess = 0x80000000U;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 7)
        {
            throw new InvalidOperationException("Expected arguments: <workerCount> <workerIterations> <durableIterations> <oplockIterations> <leaseIterations> <minimumDurationSeconds> <largePayloadLength>.");
        }

        int workerCount = ParsePositiveInt(args[0], "workerCount");
        int workerIterations = ParsePositiveInt(args[1], "workerIterations");
        int durableIterations = ParsePositiveInt(args[2], "durableIterations");
        int oplockIterations = ParsePositiveInt(args[3], "oplockIterations");
        int leaseIterations = ParsePositiveInt(args[4], "leaseIterations");
        int minimumDurationSeconds = ParsePositiveInt(args[5], "minimumDurationSeconds");
        int largePayloadLength = ParsePositiveInt(args[6], "largePayloadLength");

        string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsSoakSmoke_" + Guid.NewGuid().ToString("N"));
        string shareRoot = Path.Combine(rootPath, "SoakShare");
        Directory.CreateDirectory(shareRoot);

        int port = AllocateLoopbackPort();
        byte[] largePayload = CreateLargePayload(largePayloadLength);
        string largePayloadSha256 = Convert.ToHexString(SHA256.HashData(largePayload));
        long authenticatedSessionCount = 0;
        long treeConnectCount = 0;
        long createCount = 0;

        OpenCifsServerOptions serverOptions = new OpenCifsServerOptions
        {
            ServerName = "127.0.0.1",
            BindAddress = "127.0.0.1",
            BindPort = port,
            MinimumDialect = SmbDialect.Smb21,
            MaximumDialect = SmbDialect.Smb21
        };

        OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(serverOptions)
            .AddAccount(new OpenCifsServerAccount
            {
                UserName = UserName,
                UserDomain = UserDomain,
                Password = Password
            })
            .AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = ShareName,
                RootPath = shareRoot,
                CreateRootIfMissing = true
            })
            .ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
            {
                AuthenticatedSessionCallback = context =>
                {
                    Interlocked.Increment(ref authenticatedSessionCount);
                    return null;
                },
                TreeConnectCallback = context =>
                {
                    Interlocked.Increment(ref treeConnectCount);
                    return null;
                },
                CreateCallback = context =>
                {
                    Interlocked.Increment(ref createCount);
                    return null;
                }
            });

        await using OpenCifsServerApplication server = builder.BuildApplication(
            exception => Console.Error.WriteLine("[soak-smoke-server] " + exception.Message));

        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            await server.StartAsync(CancellationToken.None).ConfigureAwait(false);
            DateTimeOffset runUntilUtc = DateTimeOffset.UtcNow.AddSeconds(minimumDurationSeconds);

            Task<PrimaryClientWorkerResult>[] primaryClientTasks = new Task<PrimaryClientWorkerResult>[workerCount];
            for (int workerId = 0; workerId < workerCount; workerId++)
            {
                int capturedWorkerId = workerId;
                primaryClientTasks[workerId] = RunPrimaryClientWorkerAsync(
                    capturedWorkerId,
                    port,
                    workerIterations,
                    runUntilUtc,
                    largePayload,
                    largePayloadSha256);
            }

            Task<DurableWorkerResult>[] durableTasks = new Task<DurableWorkerResult>[durableIterations];
            for (int iteration = 0; iteration < durableIterations; iteration++)
            {
                int capturedIteration = iteration;
                durableTasks[iteration] = RunDurableWorkerAsync(capturedIteration, port);
            }

            Task<OplockWorkerResult>[] oplockTasks = new Task<OplockWorkerResult>[oplockIterations];
            for (int iteration = 0; iteration < oplockIterations; iteration++)
            {
                int capturedIteration = iteration;
                oplockTasks[iteration] = RunOplockWorkerAsync(capturedIteration, port);
            }

            Task<LeaseWorkerResult>[] leaseTasks = new Task<LeaseWorkerResult>[leaseIterations];
            for (int iteration = 0; iteration < leaseIterations; iteration++)
            {
                int capturedIteration = iteration;
                leaseTasks[iteration] = RunLeaseWorkerAsync(capturedIteration, port);
            }

            PrimaryClientWorkerResult[] primaryClientResults = await Task.WhenAll(primaryClientTasks).ConfigureAwait(false);
            DurableWorkerResult[] durableResults = await Task.WhenAll(durableTasks).ConfigureAwait(false);
            OplockWorkerResult[] oplockResults = await Task.WhenAll(oplockTasks).ConfigureAwait(false);
            LeaseWorkerResult[] leaseResults = await Task.WhenAll(leaseTasks).ConfigureAwait(false);
            stopwatch.Stop();

            int totalPrimaryClientConnections = primaryClientResults.Sum(static result => result.ConnectionCount);
            int totalDirectoryCreates = primaryClientResults.Sum(static result => result.DirectoryCreateCount);
            int totalLargeRoundTrips = primaryClientResults.Sum(static result => result.LargeRoundTripCount);
            int totalNonEmptyDeleteRejections = primaryClientResults.Sum(static result => result.NonEmptyDeleteRejectionCount);
            long totalBytesWritten = primaryClientResults.Sum(static result => result.BytesWritten);
            long totalBytesRead = primaryClientResults.Sum(static result => result.BytesRead);
            int totalDurableReconnects = durableResults.Sum(static result => result.DurableReconnectCount);
            int totalDetachedReadConflicts = durableResults.Sum(static result => result.DetachedReadConflictCount);
            int totalDetachedLockConflicts = durableResults.Sum(static result => result.DetachedLockConflictCount);
            int totalPostReconnectLockSuccesses = durableResults.Sum(static result => result.PostReconnectLockSuccessCount);
            int totalOplockBreaks = oplockResults.Sum(static result => result.OplockBreakCount);
            int totalOplockAcknowledgments = oplockResults.Sum(static result => result.OplockAcknowledgmentCount);
            int totalLeaseBreaks = leaseResults.Sum(static result => result.LeaseBreakCount);
            int totalLeaseAcknowledgments = leaseResults.Sum(static result => result.LeaseAcknowledgmentCount);

            Console.WriteLine(JsonSerializer.Serialize(new
            {
                MinimumDialect = serverOptions.MinimumDialect.ToString(),
                MaximumDialect = serverOptions.MaximumDialect.ToString(),
                Port = port,
                WorkerCount = workerCount,
                WorkerIterations = workerIterations,
                DurableIterations = durableIterations,
                OplockIterations = oplockIterations,
                LeaseIterations = leaseIterations,
                MinimumDurationSeconds = minimumDurationSeconds,
                LargePayloadLength = largePayload.Length,
                LargePayloadSha256 = largePayloadSha256,
                TotalPrimaryClientConnections = totalPrimaryClientConnections,
                TotalDirectoryCreates = totalDirectoryCreates,
                TotalLargeRoundTrips = totalLargeRoundTrips,
                TotalNonEmptyDeleteRejections = totalNonEmptyDeleteRejections,
                TotalDurableReconnects = totalDurableReconnects,
                TotalDetachedReadConflicts = totalDetachedReadConflicts,
                TotalDetachedLockConflicts = totalDetachedLockConflicts,
                TotalPostReconnectLockSuccesses = totalPostReconnectLockSuccesses,
                TotalOplockBreaks = totalOplockBreaks,
                TotalOplockAcknowledgments = totalOplockAcknowledgments,
                TotalLeaseBreaks = totalLeaseBreaks,
                TotalLeaseAcknowledgments = totalLeaseAcknowledgments,
                TotalBytesWritten = totalBytesWritten,
                TotalBytesRead = totalBytesRead,
                AuthenticatedSessionCount = authenticatedSessionCount,
                TreeConnectCount = treeConnectCount,
                CreateCount = createCount,
                ElapsedMilliseconds = stopwatch.ElapsedMilliseconds
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

    private static async Task<PrimaryClientWorkerResult> RunPrimaryClientWorkerAsync(
        int workerId,
        int port,
        int workerIterations,
        DateTimeOffset runUntilUtc,
        byte[] largePayload,
        string expectedLargePayloadSha256)
    {
        PrimaryClientWorkerResult result = new PrimaryClientWorkerResult();

        for (int iteration = 0; result.ConnectionCount < workerIterations || DateTimeOffset.UtcNow < runUntilUtc; iteration++)
        {
            string workerRoot = JoinSharePath("worker-" + workerId.ToString("D2", System.Globalization.CultureInfo.InvariantCulture));
            string iterationRoot = JoinSharePath(workerRoot, "iteration-" + iteration.ToString("D3", System.Globalization.CultureInfo.InvariantCulture));
            string smallPath = JoinSharePath(iterationRoot, "hello.txt");
            string renamedSmallPath = JoinSharePath(iterationRoot, "hello-renamed.txt");
            string largePath = JoinSharePath(iterationRoot, "large.bin");
            byte[] smallPayload = Encoding.UTF8.GetBytes("hello worker " + workerId.ToString(System.Globalization.CultureInfo.InvariantCulture) + " iteration " + iteration.ToString(System.Globalization.CultureInfo.InvariantCulture));

            await using OpenCifsClient client = new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", port)
                .WithDialectRange(SmbDialect.Smb21, SmbDialect.Smb21)
                .WithSigningRequired()
                .Build();
            await client.ConnectAsync(CreateCredential()).ConfigureAwait(false);

            if (client.Session.NegotiatedDialect != SmbDialect.Smb21)
            {
                throw new InvalidOperationException("The soak-smoke primary-client worker did not negotiate SMB 2.1.");
            }

            result.ConnectionCount++;

            await client.EchoAsync().ConfigureAwait(false);
            await using (OpenCifsShareSession share = await client.OpenShareAsync(ShareName).ConfigureAwait(false))
            {
                await share.Directories.CreateAsync(workerRoot).ConfigureAwait(false);
                result.DirectoryCreateCount++;
                await share.Directories.CreateAsync(iterationRoot).ConfigureAwait(false);
                result.DirectoryCreateCount++;

                await share.Files.WriteAllBytesAsync(smallPath, smallPayload).ConfigureAwait(false);
                result.BytesWritten += smallPayload.Length;
                await share.Files.WriteAllBytesAsync(largePath, largePayload).ConfigureAwait(false);
                result.BytesWritten += largePayload.Length;

                byte[] roundTripPayload = await share.Files.ReadAllBytesAsync(largePath).ConfigureAwait(false);
                result.BytesRead += roundTripPayload.Length;
                string actualLargePayloadSha256 = Convert.ToHexString(SHA256.HashData(roundTripPayload));

                if (!StringComparer.Ordinal.Equals(actualLargePayloadSha256, expectedLargePayloadSha256))
                {
                    throw new InvalidOperationException("The soak-smoke primary-client worker large payload hash did not round-trip cleanly.");
                }

                result.LargeRoundTripCount++;

                OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync(largePath).ConfigureAwait(false);
                if (metadata.EndOfFile != checked((ulong)largePayload.Length))
                {
                    throw new InvalidOperationException("The soak-smoke primary-client worker metadata EOF length did not match the large payload length.");
                }

                OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync(iterationRoot).ConfigureAwait(false);
                EnsureContainsFile(entries, "hello.txt");
                EnsureContainsFile(entries, "large.bin");

                try
                {
                    await share.Directories.DeleteAsync(iterationRoot).ConfigureAwait(false);
                    throw new InvalidOperationException("The soak-smoke primary-client worker expected non-empty-directory delete rejection.");
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
                {
                    result.NonEmptyDeleteRejectionCount++;
                }

                await share.Files.RenameAsync(smallPath, renamedSmallPath).ConfigureAwait(false);
                await share.Files.DeleteAsync(renamedSmallPath).ConfigureAwait(false);
                await share.Files.DeleteAsync(largePath).ConfigureAwait(false);
                await share.Directories.DeleteAsync(iterationRoot).ConfigureAwait(false);
                await share.Directories.DeleteAsync(workerRoot).ConfigureAwait(false);
            }

            await client.DisconnectAsync().ConfigureAwait(false);
        }

        return result;
    }

    private static async Task<DurableWorkerResult> RunDurableWorkerAsync(int iteration, int port)
    {
        DurableWorkerResult result = new DurableWorkerResult();
        string filePath = "durable-" + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + ".bin";
        byte[] initialPayload = Encoding.UTF8.GetBytes("durable reconnect payload " + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture));
        OpenCifsClientConnection durableConnection = new OpenCifsClientConnection(CreateClientOptions(port));
        OpenCifsClientConnection? competingConnection = null;
        OpenCifsClientConnection? reconnectConnection = null;
        OpenCifsClientOpenHandle? competingOpen = null;
        OpenCifsClientOpenHandle? reconnectedOpen = null;
        OpenCifsClientOpenHandle? durableOpen = null;

        try
        {
            await durableConnection.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);

            if (durableConnection.Session.NegotiatedDialect != SmbDialect.Smb21)
            {
                throw new InvalidOperationException("The soak-smoke durable worker did not negotiate SMB 2.1.");
            }

            OpenCifsClientTreeHandle durableTree = await durableConnection.TreeConnectAsync(ShareName).ConfigureAwait(false);
            durableOpen = await durableConnection.OpenAsync(
                durableTree,
                filePath,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                requestDurableHandle: true).ConfigureAwait(false);

            uint writtenCount = await durableConnection.WriteAsync(durableOpen, initialPayload, 0).ConfigureAwait(false);
            if (writtenCount != initialPayload.Length)
            {
                throw new InvalidOperationException("The soak-smoke durable worker did not receive a full initial write acknowledgment.");
            }

            await durableConnection.FlushAsync(durableOpen).ConfigureAwait(false);
            await durableConnection.LockAsync(durableOpen, new[]
            {
                new Smb2LockElement
                {
                    Offset = 0,
                    Length = checked((ulong)initialPayload.Length),
                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                }
            }).ConfigureAwait(false);

            await SimulateAbruptDisconnectAsync(durableConnection).ConfigureAwait(false);

            competingConnection = new OpenCifsClientConnection(CreateClientOptions(port));
            await competingConnection.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);
            OpenCifsClientTreeHandle competingTree = await competingConnection.TreeConnectAsync(ShareName).ConfigureAwait(false);
            competingOpen = await competingConnection.OpenExistingPathAsync(competingTree, filePath, GenericReadAccess).ConfigureAwait(false);

            await ExpectStatusAsync(
                async () => { _ = await competingConnection.ReadAsync(competingOpen, checked((uint)initialPayload.Length), 0).ConfigureAwait(false); },
                NtStatus.FileLockConflict,
                "detached durable read conflict").ConfigureAwait(false);
            result.DetachedReadConflictCount++;

            await ExpectStatusAsync(
                () => competingConnection.LockAsync(competingOpen, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = 0,
                        Length = checked((ulong)initialPayload.Length),
                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                    }
                }),
                NtStatus.LockNotGranted,
                "detached durable lock conflict").ConfigureAwait(false);
            result.DetachedLockConflictCount++;

            reconnectConnection = new OpenCifsClientConnection(CreateClientOptions(port));
            await reconnectConnection.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);
            OpenCifsClientTreeHandle reconnectTree = await reconnectConnection.TreeConnectAsync(ShareName).ConfigureAwait(false);
            reconnectedOpen = await reconnectConnection.ReconnectDurableOpenAsync(reconnectTree, durableOpen).ConfigureAwait(false);

            byte[] reconnectedBytes = await reconnectConnection.ReadAsync(reconnectedOpen, checked((uint)initialPayload.Length), 0).ConfigureAwait(false);
            EnsureEqualBytes(initialPayload, reconnectedBytes, "reconnected durable read");

            await reconnectConnection.LockAsync(reconnectedOpen, new[]
            {
                new Smb2LockElement
                {
                    Offset = 0,
                    Length = checked((ulong)initialPayload.Length),
                    Flags = Smb2LockFlags.Unlock
                }
            }).ConfigureAwait(false);

            byte[] competingBytes = await competingConnection.ReadAsync(competingOpen, checked((uint)initialPayload.Length), 0).ConfigureAwait(false);
            EnsureEqualBytes(initialPayload, competingBytes, "post-reconnect competing read");

            await competingConnection.LockAsync(competingOpen, new[]
            {
                new Smb2LockElement
                {
                    Offset = 0,
                    Length = checked((ulong)initialPayload.Length),
                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                }
            }).ConfigureAwait(false);
            await competingConnection.LockAsync(competingOpen, new[]
            {
                new Smb2LockElement
                {
                    Offset = 0,
                    Length = checked((ulong)initialPayload.Length),
                    Flags = Smb2LockFlags.Unlock
                }
            }).ConfigureAwait(false);
            result.PostReconnectLockSuccessCount++;

            await competingConnection.CloseAsync(competingOpen).ConfigureAwait(false);
            competingOpen = null;
            await reconnectConnection.CloseAsync(reconnectedOpen).ConfigureAwait(false);
            reconnectedOpen = null;
            result.DurableReconnectCount++;
        }
        finally
        {
            await TryCloseOpenAsync(competingConnection, competingOpen).ConfigureAwait(false);
            await TryCloseOpenAsync(reconnectConnection, reconnectedOpen).ConfigureAwait(false);
            await durableConnection.DisposeAsync().ConfigureAwait(false);

            if (reconnectConnection != null)
            {
                await reconnectConnection.DisposeAsync().ConfigureAwait(false);
            }

            if (competingConnection != null)
            {
                await competingConnection.DisposeAsync().ConfigureAwait(false);
            }

            await CleanupFileAsync(port, filePath).ConfigureAwait(false);
        }

        return result;
    }

    private static async Task CleanupFileAsync(int port, string path)
    {
        await using OpenCifsClient cleanupClient = new OpenCifsClientBuilder()
            .WithServer("127.0.0.1", port)
            .WithDialectRange(SmbDialect.Smb21, SmbDialect.Smb21)
            .WithSigningRequired()
            .Build();

        try
        {
            await cleanupClient.ConnectAsync(CreateCredential()).ConfigureAwait(false);
            await using OpenCifsShareSession share = await cleanupClient.OpenShareAsync(ShareName).ConfigureAwait(false);
            await share.Files.DeleteAsync("/" + path.Replace("\\", "/", StringComparison.Ordinal)).ConfigureAwait(false);
            await cleanupClient.DisconnectAsync().ConfigureAwait(false);
        }
        catch (OpenCifsStatusException exception) when (
            exception.Status == NtStatus.NoSuchFile ||
            exception.Status == NtStatus.ObjectNameNotFound ||
            exception.Status == NtStatus.ObjectPathNotFound)
        {
        }
    }

    private static async Task<OplockWorkerResult> RunOplockWorkerAsync(int iteration, int port)
    {
        OplockWorkerResult result = new OplockWorkerResult();
        string filePath = "oplock-" + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + ".bin";
        byte[] payload = Encoding.UTF8.GetBytes("oplock churn payload " + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture));
        OpenCifsClientConnection? watcherClient = null;
        OpenCifsClientConnection? actorClient = null;
        OpenCifsClientOpenHandle? watcherOpen = null;
        OpenCifsClientOpenHandle? actorOpen = null;

        try
        {
            watcherClient = new OpenCifsClientConnection(CreateClientOptions(port));
            actorClient = new OpenCifsClientConnection(CreateClientOptions(port));
            await watcherClient.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);
            await actorClient.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);

            OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync(ShareName).ConfigureAwait(false);
            OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync(ShareName).ConfigureAwait(false);

            watcherOpen = await watcherClient.OpenAsync(
                watcherTree,
                filePath,
                desiredAccess: 0xC0010000U,
                shareAccess: 0x00000007U,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
            TestGrantedOplockLevel(watcherOpen.OplockLevel, Smb2OplockLevel.Exclusive, "exclusive oplock grant");

            uint writtenCount = await watcherClient.WriteAsync(watcherOpen, payload, 0).ConfigureAwait(false);
            if (writtenCount != payload.Length)
            {
                throw new InvalidOperationException("The soak-smoke oplock worker did not receive a full seed write acknowledgment.");
            }

            await watcherClient.FlushAsync(watcherOpen).ConfigureAwait(false);

            using CancellationTokenSource breakTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            Task<OpenCifsClientOplockBreakNotification> breakTask = watcherClient.WaitForOplockBreakAsync(breakTokenSource.Token);

            await Task.Delay(100).ConfigureAwait(false);
            actorOpen = await actorClient.OpenAsync(
                actorTree,
                filePath,
                desiredAccess: GenericReadAccess,
                shareAccess: 0x00000007U,
                createDisposition: Smb2CreateDisposition.Open).ConfigureAwait(false);

            OpenCifsClientOplockBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
            TestGrantedOplockLevel(breakNotification.PreviousOplockLevel, Smb2OplockLevel.Exclusive, "exclusive oplock break previous level");
            TestGrantedOplockLevel(breakNotification.NewOplockLevel, Smb2OplockLevel.None, "exclusive oplock break new level");
            TestGrantedOplockLevel(watcherOpen.OplockLevel, Smb2OplockLevel.None, "post-break watcher oplock level");
            TestGrantedOplockLevel(actorOpen.OplockLevel, Smb2OplockLevel.None, "post-break competing oplock level");

            result.OplockBreakCount++;
            if (breakNotification.WasAcknowledged)
            {
                result.OplockAcknowledgmentCount++;
            }

            await actorClient.CloseAsync(actorOpen).ConfigureAwait(false);
            actorOpen = null;
            await watcherClient.CloseAsync(watcherOpen).ConfigureAwait(false);
            watcherOpen = null;
            await actorClient.TreeDisconnectAsync(actorTree).ConfigureAwait(false);
            await watcherClient.TreeDisconnectAsync(watcherTree).ConfigureAwait(false);
        }
        finally
        {
            await TryCloseOpenAsync(actorClient, actorOpen).ConfigureAwait(false);
            await TryCloseOpenAsync(watcherClient, watcherOpen).ConfigureAwait(false);

            if (actorClient != null)
            {
                await actorClient.DisposeAsync().ConfigureAwait(false);
            }

            if (watcherClient != null)
            {
                await watcherClient.DisposeAsync().ConfigureAwait(false);
            }

            await CleanupFileAsync(port, filePath).ConfigureAwait(false);
        }

        return result;
    }

    private static async Task<LeaseWorkerResult> RunLeaseWorkerAsync(int iteration, int port)
    {
        LeaseWorkerResult result = new LeaseWorkerResult();
        string filePath = "lease-" + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + ".bin";
        byte[] payload = Encoding.UTF8.GetBytes("lease churn payload " + iteration.ToString("D2", System.Globalization.CultureInfo.InvariantCulture));
        OpenCifsClientConnection? watcherClient = null;
        OpenCifsClientConnection? actorClient = null;
        OpenCifsClientOpenHandle? watcherOpen = null;
        OpenCifsClientOpenHandle? actorOpen = null;

        try
        {
            watcherClient = new OpenCifsClientConnection(CreateClientOptions(port));
            actorClient = new OpenCifsClientConnection(CreateClientOptions(port));
            await watcherClient.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);
            await actorClient.ConnectAndAuthenticateAsync(CreateCredential()).ConfigureAwait(false);

            OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync(ShareName).ConfigureAwait(false);
            OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync(ShareName).ConfigureAwait(false);

            watcherOpen = await watcherClient.OpenAsync(
                watcherTree,
                filePath,
                desiredAccess: 0xC0010000U,
                shareAccess: 0x00000007U,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                requestedOplockLevel: Smb2OplockLevel.Lease,
                requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching).ConfigureAwait(false);
            TestGrantedOplockLevel(watcherOpen.OplockLevel, Smb2OplockLevel.Lease, "lease-backed open oplock level");
            TestGrantedLeaseState(
                watcherOpen.LeaseState,
                Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                "lease-backed open granted state");

            uint writtenCount = await watcherClient.WriteAsync(watcherOpen, payload, 0).ConfigureAwait(false);
            if (writtenCount != payload.Length)
            {
                throw new InvalidOperationException("The soak-smoke lease worker did not receive a full seed write acknowledgment.");
            }

            await watcherClient.FlushAsync(watcherOpen).ConfigureAwait(false);

            using CancellationTokenSource breakTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            Task<OpenCifsClientLeaseBreakNotification> breakTask = watcherClient.WaitForLeaseBreakAsync(breakTokenSource.Token);

            await Task.Delay(100).ConfigureAwait(false);
            actorOpen = await actorClient.OpenAsync(
                actorTree,
                filePath,
                desiredAccess: GenericReadAccess,
                shareAccess: 0x00000007U,
                createDisposition: Smb2CreateDisposition.Open).ConfigureAwait(false);

            OpenCifsClientLeaseBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
            TestGrantedLeaseState(
                breakNotification.PreviousLeaseState,
                Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                "lease break previous state");
            TestGrantedLeaseState(breakNotification.NewLeaseState, Smb2LeaseState.None, "lease break new state");
            TestGrantedLeaseState(watcherOpen.LeaseState, Smb2LeaseState.None, "post-break watcher lease state");
            TestGrantedOplockLevel(actorOpen.OplockLevel, Smb2OplockLevel.None, "post-break competing lease oplock level");

            result.LeaseBreakCount++;
            if (breakNotification.WasAcknowledged)
            {
                result.LeaseAcknowledgmentCount++;
            }

            await actorClient.CloseAsync(actorOpen).ConfigureAwait(false);
            actorOpen = null;
            await watcherClient.CloseAsync(watcherOpen).ConfigureAwait(false);
            watcherOpen = null;
            await actorClient.TreeDisconnectAsync(actorTree).ConfigureAwait(false);
            await watcherClient.TreeDisconnectAsync(watcherTree).ConfigureAwait(false);
        }
        finally
        {
            await TryCloseOpenAsync(actorClient, actorOpen).ConfigureAwait(false);
            await TryCloseOpenAsync(watcherClient, watcherOpen).ConfigureAwait(false);

            if (actorClient != null)
            {
                await actorClient.DisposeAsync().ConfigureAwait(false);
            }

            if (watcherClient != null)
            {
                await watcherClient.DisposeAsync().ConfigureAwait(false);
            }

            await CleanupFileAsync(port, filePath).ConfigureAwait(false);
        }

        return result;
    }

    private static async Task TryCloseOpenAsync(OpenCifsClientConnection? connection, OpenCifsClientOpenHandle? openHandle)
    {
        if (connection == null || openHandle == null)
        {
            return;
        }

        try
        {
            await connection.CloseAsync(openHandle).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static async Task ExpectStatusAsync(Func<Task> operation, NtStatus expectedStatus, string operationName)
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (OpenCifsStatusException exception) when (exception.Status == expectedStatus)
        {
            return;
        }

        throw new InvalidOperationException("Expected " + operationName + " to fail with NTSTATUS " + expectedStatus + ".");
    }

    private static async Task SimulateAbruptDisconnectAsync(OpenCifsClientConnection connection)
    {
        MethodInfo? method = typeof(OpenCifsClientConnection).GetMethod(
            "SimulateTransportDisconnectAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);

        if (method == null)
        {
            throw new InvalidOperationException("The soak-smoke durable worker could not locate the abrupt-disconnect helper.");
        }

        object? invocationResult = method.Invoke(connection, Array.Empty<object>());
        if (invocationResult is not Task disconnectTask)
        {
            throw new InvalidOperationException("The soak-smoke durable worker abrupt-disconnect helper did not return a task.");
        }

        await disconnectTask.ConfigureAwait(false);
    }

    private static OpenCifsClientOptions CreateClientOptions(int port)
    {
        return new OpenCifsClientOptions
        {
            ServerName = "127.0.0.1",
            ServerPort = port,
            MinimumDialect = SmbDialect.Smb21,
            MaximumDialect = SmbDialect.Smb21
        };
    }

    private static OpenCifsClientCredential CreateCredential()
    {
        return new OpenCifsClientCredential
        {
            UserName = UserName,
            UserDomain = UserDomain,
            Password = Password
        };
    }

    private static void EnsureContainsFile(OpenCifsClientDirectoryEntry[] entries, string expectedFileName)
    {
        if (!entries.Any(entry => StringComparer.OrdinalIgnoreCase.Equals(entry.FileName, expectedFileName)))
        {
            throw new InvalidOperationException("The soak-smoke directory enumeration did not return " + expectedFileName + ".");
        }
    }

    private static void TestGrantedOplockLevel(Smb2OplockLevel actual, Smb2OplockLevel expected, string operationName)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(operationName + " returned oplock level " + actual + " instead of " + expected + ".");
        }
    }

    private static void TestGrantedLeaseState(Smb2LeaseState actual, Smb2LeaseState expected, string operationName)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(operationName + " returned lease state " + actual + " instead of " + expected + ".");
        }
    }

    private static void EnsureEqualBytes(byte[] expected, byte[] actual, string operationName)
    {
        if (expected.Length != actual.Length)
        {
            throw new InvalidOperationException(operationName + " returned a different byte length than expected.");
        }

        for (int index = 0; index < expected.Length; index++)
        {
            if (expected[index] != actual[index])
            {
                throw new InvalidOperationException(operationName + " returned different payload bytes than expected.");
            }
        }
    }

    private static byte[] CreateLargePayload(int length)
    {
        byte[] payload = new byte[length];

        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)((index * 31) % 251));
        }

        return payload;
    }

    private static string JoinRelativePath(params string[] segments)
    {
        return string.Join("\\", segments.Where(static segment => !string.IsNullOrWhiteSpace(segment)));
    }

    private static string JoinSharePath(params string[] segments)
    {
        string[] normalizedSegments = segments
            .Where(static segment => !string.IsNullOrWhiteSpace(segment))
            .Select(static segment => segment.Trim('/'))
            .Where(static segment => segment.Length > 0)
            .ToArray();
        return "/" + string.Join("/", normalizedSegments);
    }

    private static int ParsePositiveInt(string value, string argumentName)
    {
        if (!int.TryParse(value, out int parsedValue) || parsedValue < 1)
        {
            throw new InvalidOperationException("Expected a positive integer for " + argumentName + ".");
        }

        return parsedValue;
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

    private sealed class PrimaryClientWorkerResult
    {
        public int ConnectionCount { get; set; }

        public int DirectoryCreateCount { get; set; }

        public int LargeRoundTripCount { get; set; }

        public int NonEmptyDeleteRejectionCount { get; set; }

        public long BytesWritten { get; set; }

        public long BytesRead { get; set; }
    }

    private sealed class DurableWorkerResult
    {
        public int DurableReconnectCount { get; set; }

        public int DetachedReadConflictCount { get; set; }

        public int DetachedLockConflictCount { get; set; }

        public int PostReconnectLockSuccessCount { get; set; }
    }

    private sealed class OplockWorkerResult
    {
        public int OplockBreakCount { get; set; }

        public int OplockAcknowledgmentCount { get; set; }
    }

    private sealed class LeaseWorkerResult
    {
        public int LeaseBreakCount { get; set; }

        public int LeaseAcknowledgmentCount { get; set; }
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

dotnet run --project $projectPath --configuration $Configuration --framework $Framework --no-build --no-restore -- `
    $WorkerCount `
    $WorkerIterations `
    $DurableIterations `
    $OplockIterations `
    $LeaseIterations `
    $MinimumDurationSeconds `
    $LargePayloadLength | Tee-Object -FilePath $resultPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Soak smoke completed. Evidence:"
Write-Host "  $resultPath"

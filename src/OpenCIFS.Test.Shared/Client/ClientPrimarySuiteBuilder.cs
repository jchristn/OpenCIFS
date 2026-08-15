namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientPrimarySuiteBuilder
    {
        /// <summary>
        /// Build the aligned primary client surface suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientPrimarySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Primary",
                displayName: "Client primary happy-path surface",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceBuildsImmutableSettingsAndExposesAlignedApis",
                        displayName: "Client primary surface builds immutable settings and exposes aligned builder, client, and share-session APIs",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSettings settings = new OpenCifsClientBuilder()
                                .WithServer("files.example.test", 1445)
                                .WithDialectRange(SmbDialect.Smb21, SmbDialect.Smb21)
                                .WithSigningRequired()
                                .WithPreferredEncryption(false)
                                .WithConnectTimeoutMs(12345)
                                .WithDfsSiteName("Default-First-Site-Name")
                                .BuildSettings();

                            TestAssertions.Equal("files.example.test", settings.ServerName, "Unexpected immutable client settings server name.");
                            TestAssertions.Equal(1445, settings.ServerPort, "Unexpected immutable client settings port.");
                            TestAssertions.Equal(SmbDialect.Smb21, settings.MinimumDialect, "Unexpected immutable client settings minimum dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, settings.MaximumDialect, "Unexpected immutable client settings maximum dialect.");
                            TestAssertions.True(settings.RequireSigning, "Expected immutable client settings to preserve signing requirements.");
                            TestAssertions.False(settings.PreferEncryption, "Expected immutable client settings to preserve encryption preference overrides.");
                            TestAssertions.Equal(12345, settings.ConnectTimeoutMs, "Unexpected immutable client settings timeout.");
                            TestAssertions.Equal("Default-First-Site-Name", settings.DfsSiteName, "Unexpected immutable client settings DFS site name.");

                            if (typeof(OpenCifsClientSettings).GetProperty(nameof(OpenCifsClientSettings.ServerName))?.CanWrite == true)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClientSettings to remain immutable.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.ConnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose ConnectAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryConnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryConnectAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.OpenShareAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose OpenShareAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryOpenShareAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryOpenShareAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.EnumerateSharesAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose EnumerateSharesAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryEnumerateSharesAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryEnumerateSharesAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.GetShareInfoAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose GetShareInfoAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryGetShareInfoAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryGetShareInfoAsync.");
                            }

                            if (typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Files)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Directories)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Metadata)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Locks)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsShareSession to expose Files, Directories, Metadata, and Locks.");
                            }

                            if (typeof(OpenCifsShareFileOperations).GetMethod(nameof(OpenCifsShareFileOperations.TryReadAllBytesAsync)) == null ||
                                typeof(OpenCifsShareDirectoryOperations).GetMethod(nameof(OpenCifsShareDirectoryOperations.TryCreateAsync)) == null ||
                                typeof(OpenCifsShareMetadataOperations).GetMethod(nameof(OpenCifsShareMetadataOperations.TryGetAttributesAsync)) == null ||
                                typeof(OpenCifsShareLockOperations).GetMethod(nameof(OpenCifsShareLockOperations.TryAcquireExclusiveAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected grouped primary client operations to expose Try...Async result-envelope companions.");
                            }

                            if (typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.IsSuccess)) == null ||
                                typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.ErrorCategory)) == null ||
                                typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.Status)) == null ||
                                typeof(OpenCifsClientResult<byte[]>).GetProperty(nameof(OpenCifsClientResult<byte[]>.Value)) == null)
                            {
                                throw new InvalidOperationException("Expected the primary client result-envelope types to expose success, category, status, and value members.");
                            }

                            OpenCifsPreviewAttribute? clientPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClient), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? shareSessionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsShareSession), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (clientPreview != null || shareSessionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the aligned primary client surface to remain outside preview-only markers.");
                            }

                            await using OpenCifsClient client = new OpenCifsClientBuilder()
                                .WithServer("127.0.0.1", 4450)
                                .Build();
                            TestAssertions.Equal("127.0.0.1", client.Settings.ServerName, "Unexpected primary client server setting.");
                            TestAssertions.Equal(4450, client.Settings.ServerPort, "Unexpected primary client port setting.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySampleExistsAndUsesAlignedHighLevelSurface",
                        displayName: "Client primary sample exists and uses the aligned high-level surface without low-level primitives",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string samplePath = RepositoryPaths.FromRoot(Path.Combine("docs", "samples", "OpenCifsClientHappyPath.cs"));
                            string resultEnvelopeSamplePath = RepositoryPaths.FromRoot(Path.Combine("docs", "samples", "OpenCifsClientResultEnvelopeHappyPath.cs"));
                            FileAssertions.AssertExists(samplePath);
                            FileAssertions.AssertExists(resultEnvelopeSamplePath);
                            string sampleCode = File.ReadAllText(samplePath);
                            string resultEnvelopeSampleCode = File.ReadAllText(resultEnvelopeSamplePath);

                            if (!sampleCode.Contains("OpenCifsClientBuilder", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsClient", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsShareSession", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".OpenShareAsync(", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Files.", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Directories.", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Metadata.", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsStatusException", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated client happy-path sample to use the aligned builder -> client -> share-session surface.");
                            }

                            if (sampleCode.Contains("OpenCifsClientConnection", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientSession", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientTreeHandle", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientOpenHandle", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated client happy-path sample to avoid low-level connection, session, tree, and open primitives.");
                            }

                            if (!resultEnvelopeSampleCode.Contains(".TryConnectAsync(", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains(".TryOpenShareAsync(", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains("OpenCifsClientResult", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains("GetValueOrThrow", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated non-throwing client sample to use the primary Try...Async result-envelope surface.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceConnectsAndHandlesShareScopedPathFirstOperations",
                        displayName: "Client primary surface connects and handles share-scoped path-first file, directory, metadata, and lock operations",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimary_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.EchoAsync(token).ConfigureAwait(false);

                                await using OpenCifsShareSession share = await client.OpenShareAsync("public", token).ConfigureAwait(false);
                                await share.Directories.CreateAsync("/docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("primary-surface-network-data");
                                await share.Files.WriteAllBytesAsync("/docs/sample.txt", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await share.Files.ReadAllBytesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the primary client surface to round-trip the file payload.");

                                OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(checked((ulong)expectedBytes.Length), metadata.EndOfFile, "Unexpected primary client metadata EOF value.");

                                OpenCifsClientDirectoryEntry[] directoryEntries = await share.Directories.EnumerateAsync("/docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the primary client surface to enumerate the created file.");
                                TestAssertions.Equal("sample.txt", directoryEntries[0].FileName, "Unexpected primary client directory entry name.");

                                OpenCifsShareFileLock shareLock = await share.Locks.AcquireExclusiveAsync("/docs/sample.txt", 0, 4, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(shareLock.IsReleased, "Expected the grouped lock surface to keep the file lock alive until release.");
                                await shareLock.ReleaseAsync(token).ConfigureAwait(false);
                                TestAssertions.True(shareLock.IsReleased, "Expected the grouped lock surface to report a released file lock after release.");

                                await share.Files.RenameAsync("/docs/sample.txt", "/docs/sample-renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                await share.Files.DeleteAsync("/docs/sample-renamed.txt", token).ConfigureAwait(false);
                                await share.Directories.DeleteAsync("/docs", token).ConfigureAwait(false);
                                await client.DisconnectAsync(token).ConfigureAwait(false);

                                string persistedPath = Path.Combine(sharePath, "docs", "sample-renamed.txt");
                                TestAssertions.False(File.Exists(persistedPath), "Expected the primary client surface to clean up the renamed file.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceTryApisReturnResultEnvelopesAcrossSuccessAndFailureFlows",
                        displayName: "Client primary surface Try APIs return result envelopes across success and failure flows",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryTry_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                OpenCifsClientResult connectResult = await client.TryConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(connectResult.IsSuccess, "Expected TryConnectAsync to succeed against the live listener.");

                                OpenCifsClientResult echoResult = await client.TryEchoAsync(token).ConfigureAwait(false);
                                TestAssertions.True(echoResult.IsSuccess, "Expected TryEchoAsync to succeed on the authenticated primary client surface.");

                                OpenCifsClientResult<OpenCifsShareSession> shareResult = await client.TryOpenShareAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(shareResult.IsSuccess, "Expected TryOpenShareAsync to succeed for the public share.");

                                await using OpenCifsShareSession share = shareResult.GetValueOrThrow();
                                OpenCifsClientResult createDirectoryResult = await share.Directories.TryCreateAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.True(createDirectoryResult.IsSuccess, "Expected TryCreateAsync to succeed for a new directory.");

                                await TestAssertions.ThrowsAsync<ArgumentException>(
                                    () => share.Metadata.TrySetBasicInfoAsync("/docs", cancellationToken: token),
                                    "Expected TrySetBasicInfoAsync to preserve local argument-validation failures instead of flattening them into a result envelope.").ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("result-envelope-network-data");
                                OpenCifsClientResult writeResult = await share.Files.TryWriteAllBytesAsync("/docs/sample.txt", expectedBytes, token).ConfigureAwait(false);
                                TestAssertions.True(writeResult.IsSuccess, "Expected TryWriteAllBytesAsync to succeed for the sample file.");

                                OpenCifsClientResult<byte[]> readResult = await share.Files.TryReadAllBytesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True(readResult.IsSuccess, "Expected TryReadAllBytesAsync to succeed for the sample file.");
                                TestAssertions.SequenceEqual(expectedBytes, readResult.GetValueOrThrow(), "Expected the TryReadAllBytesAsync envelope to preserve the file payload.");

                                OpenCifsClientResult<OpenCifsClientFileMetadata> metadataResult = await share.Metadata.TryGetAttributesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True(metadataResult.IsSuccess, "Expected TryGetAttributesAsync to succeed for the sample file.");
                                TestAssertions.Equal(checked((ulong)expectedBytes.Length), metadataResult.GetValueOrThrow().EndOfFile, "Unexpected TryGetAttributesAsync EOF value.");

                                OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> enumerateResult = await share.Directories.TryEnumerateAsync("/docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.True(enumerateResult.IsSuccess, "Expected TryEnumerateAsync to succeed for the sample directory.");
                                TestAssertions.Equal(1, enumerateResult.GetValueOrThrow().Length, "Expected the TryEnumerateAsync envelope to return the created file.");

                                OpenCifsClientResult<OpenCifsShareFileLock> lockResult = await share.Locks.TryAcquireExclusiveAsync("/docs/sample.txt", 0, 4, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(lockResult.IsSuccess, "Expected TryAcquireExclusiveAsync to succeed for the sample file.");
                                OpenCifsShareFileLock shareLock = lockResult.GetValueOrThrow();
                                TestAssertions.False(shareLock.IsReleased, "Expected the TryAcquireExclusiveAsync envelope to return a live file lock.");
                                await shareLock.ReleaseAsync(token).ConfigureAwait(false);

                                OpenCifsClientResult missingFileResult = await share.Files.TryReadAllBytesAsync("/docs/missing.txt", token).ConfigureAwait(false);
                                TestAssertions.False(missingFileResult.IsSuccess, "Expected TryReadAllBytesAsync to report a failure envelope for a missing file.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingFileResult.ErrorCategory!.Value, "Expected missing-file read failures to preserve the normalized NotFound category.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingFileResult.Status!.Value, "Expected missing-file read failures to preserve the server NTSTATUS.");
                                TestAssertions.Equal(Smb2Command.Create, missingFileResult.Command!.Value, "Expected missing-file read failures to preserve the failing SMB2 command.");

                                OpenCifsClientResult wrongDeleteResult = await share.Directories.TryDeleteAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.False(wrongDeleteResult.IsSuccess, "Expected TryDeleteAsync to return a failure envelope for a non-empty directory.");
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, wrongDeleteResult.ErrorCategory!.Value, "Expected non-empty directory delete failures to map to Conflict.");
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, wrongDeleteResult.Status!.Value, "Expected non-empty directory delete failures to preserve STATUS_DIRECTORY_NOT_EMPTY.");
                                TestAssertions.True(wrongDeleteResult.Exception is OpenCifsStatusException, "Expected non-empty directory delete failures to retain the typed SMB status exception.");
                                TestAssertions.True(wrongDeleteResult.ErrorData.Length == 0, "Expected bounded directory delete failures to expose empty SMB2 error-data bytes.");

                                OpenCifsClientResult renameResult = await share.Files.TryRenameAsync("/docs/sample.txt", "/docs/sample-renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(renameResult.IsSuccess, "Expected TryRenameAsync to succeed for the sample file.");

                                OpenCifsClientResult deleteFileResult = await share.Files.TryDeleteAsync("/docs/sample-renamed.txt", token).ConfigureAwait(false);
                                TestAssertions.True(deleteFileResult.IsSuccess, "Expected TryDeleteAsync to succeed for the renamed file.");

                                OpenCifsClientResult deleteDirectoryResult = await share.Directories.TryDeleteAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.True(deleteDirectoryResult.IsSuccess, "Expected TryDeleteAsync to succeed for the now-empty directory.");

                                OpenCifsClientResult disconnectResult = await client.TryDisconnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(disconnectResult.IsSuccess, "Expected TryDisconnectAsync to succeed after the primary result-envelope flow.");

                                OpenCifsClientResult postDisconnectCreateResult = await share.Directories.TryCreateAsync("/after-disconnect", token).ConfigureAwait(false);
                                TestAssertions.False(postDisconnectCreateResult.IsSuccess, "Expected TryCreateAsync to report a state failure after disconnect.");
                                TestAssertions.True(postDisconnectCreateResult.Exception is OpenCifsClientStateException, "Expected post-disconnect share-session failures to preserve the typed client-state exception.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceEnumeratesManagedSharesThroughOpenCifsIpcAndSrvsvc",
                        displayName: "Client primary surface enumerates managed shares through OpenCIFS IPC$ and srvsvc",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryBrowse_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(token).ConfigureAwait(false);
                                TestAssertions.True(sharesResult.IsSuccess, "Expected share browsing to succeed when the managed server explicitly registers the bounded IPC$/srvsvc endpoint.");

                                OpenCifsRemoteShareInfo[] shares = sharesResult.Value!;
                                TestAssertions.Equal(2, shares.Length, "Expected the bounded managed share-browse slice to expose the public data share and IPC$.");
                                TestAssertions.True(shares.Any(share => string.Equals(share.Name, "public", StringComparison.OrdinalIgnoreCase)), "Expected the bounded managed share-browse slice to include the public data share.");
                                TestAssertions.True(shares.Any(share => string.Equals(share.Name, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected the bounded managed share-browse slice to include IPC$ for named-pipe transport.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceShareBrowsingReportsMissingIpcSupportCleanly",
                        displayName: "Client primary surface share browsing reports a typed failure when the remote server does not expose IPC$",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryBrowse_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(token).ConfigureAwait(false);
                                TestAssertions.False(sharesResult.IsSuccess, "Expected share browsing to fail when the managed test listener omits the bounded IPC$/srvsvc endpoint registration.");
                                TestAssertions.True(sharesResult.Exception is OpenCifsStatusException, "Expected missing IPC$ support to surface as a typed SMB status exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, sharesResult.ErrorCategory!.Value, "Expected missing IPC$ support to normalize to NotFound.");
                                TestAssertions.Equal(Smb2Command.TreeConnect, sharesResult.Command!.Value, "Expected missing IPC$ support to fail during the IPC$ tree connect.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, sharesResult.Status!.Value, "Expected the missing IPC$ tree connect to preserve STATUS_OBJECT_NAME_NOT_FOUND when the managed listener does not register IPC$.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceTransceivesManagedNamedPipeThroughIpc",
                        displayName: "Client primary surface transceives a managed named pipe through IPC$",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryPipe_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true,
                                enableUtf8EchoPipe: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                byte[] requestBytes = System.Text.Encoding.UTF8.GetBytes("hello pipe");
                                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(
                                    OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName,
                                    requestBytes,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(transceiveResult.IsSuccess, "Expected the bounded managed named-pipe echo endpoint to transceive successfully through IPC$.");
                                TestAssertions.SequenceEqual(requestBytes, transceiveResult.Value!, "Expected the bounded managed UTF-8 echo endpoint to return the original payload bytes.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceQueriesManagedShareInfoThroughOpenCifsIpcAndSrvsvc",
                        displayName: "Client primary surface queries managed share info through OpenCIFS IPC$ and srvsvc",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryShareInfo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(shareInfoResult.IsSuccess, "Expected bounded SRVSVC share-info queries to succeed when the managed server explicitly registers the bounded IPC$/srvsvc endpoint.");

                                OpenCifsRemoteShareInfo shareInfo = shareInfoResult.Value!;
                                TestAssertions.Equal("public", shareInfo.Name, "Unexpected managed SRVSVC share-info name.");
                                TestAssertions.Equal("disk", shareInfo.Kind, "Unexpected managed SRVSVC share-info kind.");
                                TestAssertions.True(shareInfo.HasDetailedInformation, "Expected bounded SRVSVC share-info queries to populate detailed fields.");
                                TestAssertions.Equal((uint)0, shareInfo.Permissions!.Value, "Unexpected managed SRVSVC share-info permissions.");
                                TestAssertions.Equal(UInt32.MaxValue, shareInfo.MaximumUses!.Value, "Unexpected managed SRVSVC share-info maximum-use value.");
                                TestAssertions.Equal((uint)0, shareInfo.CurrentUses!.Value, "Unexpected managed SRVSVC share-info current-use value.");
                                TestAssertions.Equal(sharePath, shareInfo.LocalPath, "Unexpected managed SRVSVC share-info local path.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceShareInfoReportsMissingShareCleanly",
                        displayName: "Client primary surface share info reports a typed failure when the target share is missing",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryShareInfo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync("missing", token).ConfigureAwait(false);
                                TestAssertions.False(shareInfoResult.IsSuccess, "Expected bounded SRVSVC share-info queries to fail when the target share is missing.");
                                TestAssertions.True(shareInfoResult.Exception is OpenCifsClientRpcException, "Expected bounded SRVSVC share-info missing-share failures to surface as a typed RPC exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, shareInfoResult.ErrorCategory!.Value, "Expected bounded SRVSVC share-info missing-share failures to normalize to NotFound.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceNamedPipeTransceiveReportsMissingPipeCleanly",
                        displayName: "Client primary surface named-pipe transceive reports a typed failure when the target pipe is missing",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryPipe_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(
                                    OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName,
                                    System.Text.Encoding.UTF8.GetBytes("missing"),
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(transceiveResult.IsSuccess, "Expected the bounded named-pipe transceive slice to fail when the requested pipe endpoint is not registered.");
                                TestAssertions.True(transceiveResult.Exception is OpenCifsStatusException, "Expected missing named-pipe endpoints to surface as a typed SMB status exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, transceiveResult.ErrorCategory!.Value, "Expected missing named-pipe endpoints to normalize to NotFound.");
                                TestAssertions.Equal(Smb2Command.Create, transceiveResult.Command!.Value, "Expected missing named-pipe endpoint failures to occur during the pipe create request.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, transceiveResult.Status!.Value, "Expected the missing named-pipe endpoint failure to preserve STATUS_OBJECT_NAME_NOT_FOUND.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceSmb311PreviewIsToleratedByLiveListenerAndCompletesAuthenticatedSession",
                        displayName: "Client primary surface SMB 3.1.1 preview is tolerated by a live listener and completes an authenticated session via SMB 3.0.2 fallback",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimarySmb311Preview_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithSmb311Preview()
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("smb311preview.txt", new byte[] { 0x53, 0x4D, 0x42, 0x33 }, token).ConfigureAwait(false);
                                byte[] payload = await share.Files.ReadAllBytesAsync("smb311preview.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(new byte[] { 0x53, 0x4D, 0x42, 0x33 }, payload, "Expected SMB 3.1.1 preview client to complete a write+read round trip against an existing tolerance server.");
                                await client.DisconnectAsync(token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceSmb311PreviewBothSidesOptedInNegotiatesSmb311AndCompletesAuthenticatedSession",
                        displayName: "Client primary surface SMB 3.1.1 preview with both client and server opted in negotiates SMB 3.1.1 and completes an authenticated session under the derived SMB 3.1.1 keys",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimarySmb311BothSides_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableSmb311Preview: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithSmb311Preview()
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(client.Session.NegotiatedDialect.HasValue, "Expected an authenticated SMB 3.1.1 preview session to have a negotiated dialect.");
                                TestAssertions.Equal(SmbDialect.Smb311, client.Session.NegotiatedDialect!.Value, "Expected both-sides-opted-in SMB 3.1.1 preview to actually negotiate the SMB 3.1.1 dialect end-to-end.");
                                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("smb311preview-bothsides.txt", new byte[] { 0x42, 0x4F, 0x54, 0x48 }, token).ConfigureAwait(false);
                                byte[] payload = await share.Files.ReadAllBytesAsync("smb311preview-bothsides.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(new byte[] { 0x42, 0x4F, 0x54, 0x48 }, payload, "Expected SMB 3.1.1 preview client+server to complete an encrypted write+read round trip under negotiated SMB 3.1.1.");
                                await client.DisconnectAsync(token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceHandlesShareRootPathsThroughBoundedSameServerDfsRootReferrals",
                        displayName: "Client primary surface handles share-root paths through bounded same-server DFS root referrals",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsRoot_" + Guid.NewGuid().ToString("N"));
                            string sharePath = Path.Combine(rootPath, "public");
                            string resolvedSharePath = Path.Combine(rootPath, "resolved");
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(resolvedSharePath);
                            Directory.CreateDirectory(Path.Combine(resolvedSharePath, "root"));
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                NamespacePath = "/",
                                TargetServerName = "127.0.0.1",
                                TargetShareName = "resolved",
                                TargetPath = "/root",
                                TimeToLiveSeconds = 600
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                dfsReferral: referral,
                                additionalShares: new OpenCifsServerFileSystemShare[]
                                {
                                    new OpenCifsServerFileSystemShare
                                    {
                                        ShareName = "resolved",
                                        RootPath = resolvedSharePath,
                                        CreateRootIfMissing = true
                                    }
                                }).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                                TestAssertions.True(share.AdvancedTreeHandle.IsDfs, "Expected a share with configured DFS referrals to advertise the DFS share flag to the primary client surface.");
                                TestAssertions.True(share.AdvancedTreeHandle.IsDfsRoot, "Expected a share with a configured root DFS referral to advertise the DFS root share flag to the primary client surface.");

                                byte[] expectedBytes = new byte[] { 0x44, 0x46, 0x53, 0x52, 0x4F, 0x4F, 0x54 };
                                await share.Files.WriteAllBytesAsync("/report.txt", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await share.Files.ReadAllBytesAsync("/report.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected share-root DFS redirection to preserve file contents through the resolved same-server target path.");

                                OpenCifsResolvedDfsPath resolvedPath = await share.ResolvePathAsync("/report.txt", token).ConfigureAwait(false);
                                TestAssertions.True(resolvedPath.WasResolvedFromCache, "Expected share-root DFS resolution to populate the cache during the redirected write path.");
                                TestAssertions.True(resolvedPath.IsSameServer, "Expected the bounded root DFS test to stay on a same-server referral target.");
                                TestAssertions.Equal("resolved", resolvedPath.TargetShareName, "Unexpected same-server DFS root target share name.");
                                TestAssertions.Equal("root\\report.txt", resolvedPath.TargetRelativePath, "Expected share-root DFS redirection to append the unresolved suffix beneath the configured referral target path.");

                                string redirectedPath = Path.Combine(resolvedSharePath, "root", "report.txt");
                                string unredirectedPath = Path.Combine(sharePath, "report.txt");
                                TestAssertions.True(File.Exists(redirectedPath), "Expected the redirected DFS write to land beneath the configured referral target root.");
                                TestAssertions.False(File.Exists(unredirectedPath), "Expected the redirected DFS write to avoid creating the file directly beneath the original share root.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesBoundedDfsReferralWithCacheReuse",
                        displayName: "Client primary surface resolves a bounded DFS referral and reuses the resolved cache entry",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfs_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                NamespacePath = "/team",
                                TargetServerName = "files-target",
                                TargetShareName = "data",
                                TargetPath = "/team",
                                TimeToLiveSeconds = 600
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                dfsReferral: referral).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt";
                                OpenCifsResolvedDfsPath firstResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.False(firstResolution.WasResolvedFromCache, "Expected the first DFS resolution to come from a remote referral query.");
                                TestAssertions.Equal("files-target", firstResolution.TargetServerName, "Unexpected resolved DFS target server name.");
                                TestAssertions.Equal("data", firstResolution.TargetShareName, "Unexpected resolved DFS target share name.");
                                TestAssertions.True(firstResolution.TargetUncPath.EndsWith("report.txt", StringComparison.OrdinalIgnoreCase), "Expected the resolved DFS UNC path to preserve the unresolved suffix.");

                                OpenCifsResolvedDfsPath secondResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.True(secondResolution.WasResolvedFromCache, "Expected the second DFS resolution to be served from the client referral cache.");
                                TestAssertions.Equal(firstResolution.TargetUncPath, secondResolution.TargetUncPath, "Expected cached DFS resolutions to preserve the resolved target UNC path.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesBoundedDfsReferralExRequestsOnSmb3WithConfiguredSiteName",
                        displayName: "Client primary surface resolves bounded DFS referrals through DFS_GET_REFERRALS_EX on SMB3 with a configured site name",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsEx_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                NamespacePath = "/team",
                                TargetServerName = "files-target",
                                TargetShareName = "data",
                                TargetPath = "/team",
                                TimeToLiveSeconds = 600
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                minimumDialect: SmbDialect.Smb302,
                                maximumDialect: SmbDialect.Smb302,
                                dfsReferral: referral).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb302, SmbDialect.Smb302)
                                    .WithDfsSiteName("Default-First-Site-Name")
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt";
                                OpenCifsResolvedDfsPath firstResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.False(firstResolution.WasResolvedFromCache, "Expected the first DFS EX resolution to come from a remote referral query.");
                                TestAssertions.Equal("files-target", firstResolution.TargetServerName, "Unexpected DFS EX target server name.");
                                TestAssertions.Equal("data", firstResolution.TargetShareName, "Unexpected DFS EX target share name.");

                                OpenCifsResolvedDfsPath secondResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.True(secondResolution.WasResolvedFromCache, "Expected the repeated DFS EX resolution to be served from the client referral cache.");
                                TestAssertions.Equal(firstResolution.TargetUncPath, secondResolution.TargetUncPath, "Expected cached DFS EX resolutions to preserve the resolved target UNC path.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceProjectsBoundedNameListDfsReferralEntriesAndRejectsStorageResolution",
                        displayName: "Client primary surface projects bounded NameList DFS referral entries and rejects storage-path resolution for domain or DC referrals",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsNameList_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                NamespacePath = "/domain",
                                IsNameListReferral = true,
                                SpecialName = "CONTOSO",
                                ExpandedNames = new string[]
                                {
                                    "\\\\dc1.contoso.test",
                                    "\\\\dc2.contoso.test"
                                },
                                TimeToLiveSeconds = 600
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                minimumDialect: SmbDialect.Smb302,
                                maximumDialect: SmbDialect.Smb302,
                                dfsReferral: referral).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb302, SmbDialect.Smb302)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\domain";
                                OpenCifsDfsReferral[] referrals = await client.GetDfsReferralsAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.Equal(1, referrals.Length, "Expected the bounded NameList DFS path to return a single referral entry.");
                                TestAssertions.True(referrals[0].IsNameListReferral, "Expected the bounded NameList DFS path to preserve the NameList referral layout.");
                                TestAssertions.Equal("CONTOSO", referrals[0].SpecialName, "Unexpected NameList DFS special name.");
                                TestAssertions.Equal(2, referrals[0].ExpandedNames.Length, "Expected the bounded NameList DFS path to preserve both expanded names.");
                                TestAssertions.Equal("\\\\dc1.contoso.test", referrals[0].ExpandedNames[0], "Unexpected first NameList DFS expanded name.");
                                TestAssertions.Equal("\\\\dc2.contoso.test", referrals[0].ExpandedNames[1], "Unexpected second NameList DFS expanded name.");
                                TestAssertions.Equal(string.Empty, referrals[0].TargetServerName, "Expected NameList DFS referrals to avoid projecting a storage target server.");
                                TestAssertions.Equal(string.Empty, referrals[0].TargetShareName, "Expected NameList DFS referrals to avoid projecting a storage target share.");

                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => client.ResolveDfsPathAsync(dfsPath, token),
                                    "Expected bounded NameList domain or DC referrals to remain non-resolvable to a storage UNC path.").ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesRemoteMultiTargetDfsReferralByRequestedSiteNameOnSmb3ExLanes",
                        displayName: "Client primary surface resolves a remote multi-target DFS referral by the requested site name on SMB3 EX lanes",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsSite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral[] referrals = new OpenCifsServerDfsReferral[]
                            {
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    SiteName = "Branch",
                                    TargetServerName = "files-branch",
                                    TargetShareName = "data",
                                    TargetPath = "/team-branch",
                                    TimeToLiveSeconds = 600
                                },
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    SiteName = "HQ",
                                    TargetServerName = "files-hq",
                                    TargetShareName = "data",
                                    TargetPath = "/team-hq",
                                    TimeToLiveSeconds = 600
                                }
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                minimumDialect: SmbDialect.Smb302,
                                maximumDialect: SmbDialect.Smb302,
                                dfsReferrals: referrals).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb302, SmbDialect.Smb302)
                                    .WithDfsSiteName("HQ")
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt";
                                OpenCifsResolvedDfsPath firstResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.False(firstResolution.WasResolvedFromCache, "Expected the first site-aware DFS EX resolution to come from a remote referral query.");
                                TestAssertions.Equal("files-hq", firstResolution.TargetServerName, "Expected the bounded site-aware DFS path to select the requested-site target.");
                                TestAssertions.Equal("data", firstResolution.TargetShareName, "Unexpected site-aware DFS target share name.");
                                TestAssertions.Equal("\\\\files-hq\\data\\team-hq\\report.txt", firstResolution.TargetUncPath, "Expected the requested-site DFS target UNC path to preserve the unresolved suffix.");

                                OpenCifsResolvedDfsPath secondResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.True(secondResolution.WasResolvedFromCache, "Expected the repeated site-aware DFS EX resolution to be served from the client referral cache.");
                                TestAssertions.Equal(firstResolution.TargetUncPath, secondResolution.TargetUncPath, "Expected cached site-aware DFS resolution to preserve the requested-site target.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesMultiTargetDfsReferralByPreferringSameServerTargetWhenAvailable",
                        displayName: "Client primary surface resolves a multi-target DFS referral by preferring the same-server target when available",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsMultiTarget_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral[] referrals = new OpenCifsServerDfsReferral[]
                            {
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    TargetServerName = "remote-target",
                                    TargetShareName = "archive",
                                    TargetPath = "/team-remote",
                                    TimeToLiveSeconds = 600
                                },
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    TargetServerName = "127.0.0.1",
                                    TargetShareName = TestEnvironmentDefaults.DefaultShareName,
                                    TargetPath = "/resolved/team",
                                    TimeToLiveSeconds = 600
                                }
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                dfsReferrals: referrals).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt";
                                OpenCifsResolvedDfsPath firstResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.False(firstResolution.WasResolvedFromCache, "Expected the first multi-target DFS resolution to come from a remote referral query.");
                                TestAssertions.True(firstResolution.IsSameServer, "Expected bounded multi-target DFS selection to prefer the same-server target when one is available.");
                                TestAssertions.Equal("127.0.0.1", firstResolution.TargetServerName, "Unexpected same-server DFS target selection.");
                                TestAssertions.Equal(TestEnvironmentDefaults.DefaultShareName, firstResolution.TargetShareName, "Unexpected same-server DFS target share name.");
                                TestAssertions.Equal($"\\\\127.0.0.1\\{TestEnvironmentDefaults.DefaultShareName}\\resolved\\team\\report.txt", firstResolution.TargetUncPath, "Expected the preferred same-server DFS target UNC path to preserve the unresolved suffix.");

                                OpenCifsResolvedDfsPath secondResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.True(secondResolution.WasResolvedFromCache, "Expected the repeated multi-target DFS resolution to be served from the client referral cache.");
                                TestAssertions.Equal(firstResolution.TargetUncPath, secondResolution.TargetUncPath, "Expected cached multi-target DFS resolution to preserve the preferred same-server target.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesDfsReferralCacheEvictionAndPreservesMostRecentlyUsedEntryWhenCapacityIsExceeded",
                        displayName: "Client primary surface resolves DFS cache eviction and preserves the most recently used entry when capacity is exceeded",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfsEviction_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral[] referrals = new OpenCifsServerDfsReferral[]
                            {
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    TargetServerName = "files-team",
                                    TargetShareName = "data",
                                    TargetPath = "/team",
                                    TimeToLiveSeconds = 600
                                },
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/finance",
                                    TargetServerName = "files-finance",
                                    TargetShareName = "data",
                                    TargetPath = "/finance",
                                    TimeToLiveSeconds = 600
                                },
                                new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/projects",
                                    TargetServerName = "files-projects",
                                    TargetShareName = "data",
                                    TargetPath = "/projects",
                                    TimeToLiveSeconds = 600
                                }
                            };
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                dfsReferrals: referrals).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .WithDfsReferralCacheCapacity(2)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsResolvedDfsPath firstTeamResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.False(firstTeamResolution.WasResolvedFromCache, "Expected the first DFS team resolution to come from a remote referral query.");

                                OpenCifsResolvedDfsPath firstFinanceResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\finance\\budget.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.False(firstFinanceResolution.WasResolvedFromCache, "Expected the first DFS finance resolution to come from a remote referral query.");

                                OpenCifsResolvedDfsPath secondTeamResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.True(secondTeamResolution.WasResolvedFromCache, "Expected the repeated DFS team resolution to refresh the cached referral entry.");

                                OpenCifsResolvedDfsPath firstProjectsResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\projects\\plan.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.False(firstProjectsResolution.WasResolvedFromCache, "Expected the first DFS projects resolution to come from a remote referral query.");

                                OpenCifsResolvedDfsPath secondFinanceResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\finance\\budget.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.False(secondFinanceResolution.WasResolvedFromCache, "Expected the finance DFS referral to be evicted when cache capacity is exceeded.");

                                OpenCifsResolvedDfsPath secondProjectsResolution = await client.ResolveDfsPathAsync(
                                    $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\projects\\plan.txt",
                                    token).ConfigureAwait(false);
                                TestAssertions.True(secondProjectsResolution.WasResolvedFromCache, "Expected the most recently used surviving DFS referral to remain cached after an evicted referral is resolved again.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceRejectsShareSessionUseAfterDisconnect",
                        displayName: "Client primary surface rejects share-session use after the parent client disconnects",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimary_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await using OpenCifsShareSession share = await client.OpenShareAsync("public", token).ConfigureAwait(false);
                                await client.DisconnectAsync(token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => share.Directories.CreateAsync("/docs", token),
                                    "Expected the primary share session to reject path-first operations after the parent client disconnects.").ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        })
                });
        }
    }
}

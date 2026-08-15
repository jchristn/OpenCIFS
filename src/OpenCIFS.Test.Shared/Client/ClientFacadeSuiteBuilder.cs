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
    internal static class ClientFacadeSuiteBuilder
    {
        /// <summary>
        /// Build the high-level direct-TCP client facade suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientFacadeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Facade",
                displayName: "Client direct-TCP facade handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeTypesDoNotExposePreviewMarkers",
                        displayName: "Client facade types do not expose preview markers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsPreviewAttribute? facadePreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientFacade), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? directoryEntryPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientDirectoryEntry), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? fileMetadataPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientFileMetadata), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (facadePreview != null)
                            {
                                throw new InvalidOperationException("Expected the managed high-level client facade to remain outside preview-only markers.");
                            }

                            if (directoryEntryPreview != null)
                            {
                                throw new InvalidOperationException("Expected high-level facade result types to remain outside preview-only markers.");
                            }

                            if (fileMetadataPreview != null)
                            {
                                throw new InvalidOperationException("Expected high-level facade metadata types to remain outside preview-only markers.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeTracksStableConnectionSurface",
                        displayName: "Client facade tracks the stable direct-TCP connection surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions());
                            TestAssertions.True(object.ReferenceEquals(client.Options, client.Session.Options), "Expected the facade and tracked session to share the same options instance.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeConnectsOverDirectTcpAndHandlesCommonOperations",
                        displayName: "Client facade connects over direct TCP and handles authenticated echo, directory create, file write, file read, and directory enumeration",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.EchoAsync(token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-network-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAllBytesAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the direct-TCP client facade to round-trip the file payload.");

                                OpenCifsClientDirectoryEntry[] directoryEntries = await client.EnumerateDirectoryAsync("public", "docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the direct-TCP client facade to enumerate the created file.");
                                TestAssertions.Equal("sample.txt", directoryEntries[0].FileName, "Unexpected direct-TCP directory entry name.");

                                string persistedPath = Path.Combine(sharePath, "docs", "sample.txt");
                                TestAssertions.True(File.Exists(persistedPath), "Expected the direct-TCP client facade to persist the file beneath the backing share.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesLargePayloadsOverBoundedCreditWindows",
                        displayName: "Client facade handles large payload reads and writes over direct TCP when the server credit window is bounded",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token, maximumCredits: 4).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = CreateLargePayloadBytes(400000);
                                await client.WriteAllBytesAsync("public", "docs\\large.bin", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAllBytesAsync("public", "docs\\large.bin", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the direct-TCP client facade to chunk and round-trip a payload larger than the bounded server credit window allows in a single SMB2 request.");

                                string persistedPath = Path.Combine(sharePath, "docs", "large.bin");
                                TestAssertions.True(File.Exists(persistedPath), "Expected the large payload to persist beneath the backing share.");
                                TestAssertions.Equal(expectedBytes.LongLength, new FileInfo(persistedPath).Length, "Expected the persisted large payload length to match the written client data.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesMetadataRenameAndDeleteOperationsOverDirectTcp",
                        displayName: "Client facade handles metadata query, rename, and file or empty-directory delete operations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-rename-delete-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);

                                OpenCifsClientFileMetadata fileMetadata = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal("docs\\sample.txt", fileMetadata.Path, "Unexpected file metadata path.");
                                TestAssertions.False(fileMetadata.IsDirectory, "Expected file metadata to report a file.");
                                TestAssertions.False(fileMetadata.IsDeletePending, "Expected new file metadata to report a non-delete-pending file.");
                                TestAssertions.Equal((ulong)expectedBytes.Length, fileMetadata.EndOfFile, "Unexpected file metadata EOF size.");

                                await client.RenameAsync("public", "docs\\sample.txt", "docs\\renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                byte[] renamedBytes = await client.ReadAllBytesAsync("public", "docs\\renamed.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, renamedBytes, "Expected the renamed file to preserve its payload.");

                                await client.RenameAsync("public", "docs", "archive", cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientFileMetadata directoryMetadata = await client.GetMetadataAsync("public", "archive", token).ConfigureAwait(false);
                                TestAssertions.Equal("archive", directoryMetadata.Path, "Unexpected directory metadata path.");
                                TestAssertions.True(directoryMetadata.IsDirectory, "Expected directory metadata to report a directory.");

                                await client.DeleteAsync("public", "archive\\renamed.txt", token).ConfigureAwait(false);
                                OpenCifsClientDirectoryEntry[] emptiedEntries = await client.EnumerateDirectoryAsync("public", "archive", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(0, emptiedEntries.Length, "Expected the renamed directory to be empty after deleting the file.");

                                await client.DeleteAsync("public", "archive", token).ConfigureAwait(false);

                                string renamedDirectoryPath = Path.Combine(sharePath, "archive");
                                string renamedFilePath = Path.Combine(sharePath, "archive", "renamed.txt");
                                TestAssertions.False(File.Exists(renamedFilePath), "Expected the deleted file to be removed from the backing share.");
                                TestAssertions.False(Directory.Exists(renamedDirectoryPath), "Expected the deleted directory to be removed from the backing share.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesBasicInfoAndEndOfFileMutationsOverDirectTcp",
                        displayName: "Client facade handles basic-info and file-length mutations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-basic-info-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);

                                DateTime expectedLastWriteUtc = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
                                await client.SetBasicInfoAsync(
                                    "public",
                                    "docs\\sample.txt",
                                    fileAttributes: FileAttributes.Hidden,
                                    lastWriteTimeUtc: expectedLastWriteUtc,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientFileMetadata metadataAfterBasicInfo = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True((metadataAfterBasicInfo.FileAttributes & FileAttributes.Hidden) != 0, "Expected the facade basic-info mutation to set the Hidden attribute.");
                                TestAssertions.Equal(expectedLastWriteUtc, metadataAfterBasicInfo.LastWriteTimeUtc!.Value, "Expected the facade basic-info mutation to preserve the requested last-write time.");

                                await client.SetFileLengthAsync("public", "docs\\sample.txt", 6, token).ConfigureAwait(false);
                                byte[] truncatedBytes = await client.ReadAllBytesAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                byte[] expectedTruncatedBytes = new byte[6];
                                Array.Copy(expectedBytes, expectedTruncatedBytes, expectedTruncatedBytes.Length);
                                TestAssertions.SequenceEqual(expectedTruncatedBytes, truncatedBytes, "Expected the facade file-length mutation to truncate the file.");

                                OpenCifsClientFileMetadata metadataAfterResize = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(6UL, metadataAfterResize.EndOfFile, "Expected the facade file-length mutation to update EOF.");
                                TestAssertions.True((metadataAfterResize.FileAttributes & FileAttributes.Hidden) != 0, "Expected the Hidden attribute to remain set after the file-length mutation.");
                                TestAssertions.True(metadataAfterResize.LastWriteTimeUtc.HasValue, "Expected the facade metadata query to continue returning a last-write timestamp after the file-length mutation.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeCompletesDirectoryChangeNotifyOverDirectTcp",
                        displayName: "Client facade completes directory CHANGE_NOTIFY over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade watcherClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientFacade actorClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                notifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<OpenCifsClientChangeNotification[]> notifyTask = watcherClient.WaitForDirectoryChangeAsync(
                                    "public",
                                    "watched",
                                    FileNotifyChangeFilter.DirName,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.CreateDirectoryAsync("public", "watched\\child", token).ConfigureAwait(false);

                                OpenCifsClientChangeNotification[] entries = await notifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, entries.Length, "Expected the facade CHANGE_NOTIFY surface to return a single directory-create entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected facade CHANGE_NOTIFY to surface directory creation as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child", entries[0].FileName, "Unexpected facade CHANGE_NOTIFY relative path.");

                                OpenCifsClientDirectoryEntry[] enumeratedEntries = await watcherClient.EnumerateDirectoryAsync("public", "watched", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, enumeratedEntries.Length, "Expected the watched directory to remain queryable after facade CHANGE_NOTIFY completion.");
                                TestAssertions.Equal("child", enumeratedEntries[0].FileName, "Unexpected watched-directory entry after facade CHANGE_NOTIFY completion.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeCancelsChangeNotifyForNonMatchingEventsOverDirectTcp",
                        displayName: "Client facade cancels CHANGE_NOTIFY for non-matching events over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade watcherClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientFacade actorClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<OpenCifsClientChangeNotification[]> notifyTask = watcherClient.WaitForDirectoryChangeAsync(
                                    "public",
                                    "watched",
                                    FileNotifyChangeFilter.FileName,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetBasicInfoAsync("public", "watched\\sample.txt", fileAttributes: FileAttributes.Hidden, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a metadata-only mutation to leave a filename-only facade CHANGE_NOTIFY request pending.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending facade CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                OpenCifsClientDirectoryEntry[] enumeratedEntries = await watcherClient.EnumerateDirectoryAsync("public", "watched", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, enumeratedEntries.Length, "Expected the watched directory to remain queryable after cancelling facade CHANGE_NOTIFY.");
                                TestAssertions.Equal("sample.txt", enumeratedEntries[0].FileName, "Unexpected watched-directory entry after cancelling facade CHANGE_NOTIFY.");
                                TestAssertions.True((enumeratedEntries[0].FileAttributes & FileAttributes.Hidden) != 0, "Expected the non-matching metadata mutation to persist after cancelling facade CHANGE_NOTIFY.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsUseBeforeConnectAndBadCredentials",
                        displayName: "Client facade rejects operations before connect and rejects bad credentials over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            await using OpenCifsClientFacade disconnectedClient = new OpenCifsClientFacade(new OpenCifsClientOptions());
                            await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                () => disconnectedClient.EchoAsync(token),
                                "Expected authenticated direct-TCP operations to fail before connect.");

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade wrongPasswordClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                OpenCifsClientCredential wrongCredential = new OpenCifsClientCredential
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "WrongPassword!"
                                };

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => wrongPasswordClient.ConnectAsync(wrongCredential, token),
                                    "Expected the direct-TCP client facade to reject invalid credentials.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsNoOpBasicInfoAndDirectoryLengthMutationOverDirectTcp",
                        displayName: "Client facade rejects no-op basic-info requests and directory file-length mutations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", System.Text.Encoding.UTF8.GetBytes("negative-basic-info-data"), token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<ArgumentException>(
                                    () => client.SetBasicInfoAsync("public", "docs\\sample.txt", cancellationToken: token),
                                    "Expected the facade basic-info mutation to reject a no-op request.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetFileLengthAsync("public", "docs", 1, token),
                                    "Expected the facade file-length mutation to reject directory paths.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetBasicInfoAsync("public", "docs\\missing.txt", fileAttributes: FileAttributes.Hidden, cancellationToken: token),
                                    "Expected the facade basic-info mutation to reject missing paths.");

                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected failed basic-info and file-length mutations to preserve the backing file.");
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
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsMissingMetadataAndNonEmptyDirectoryDeleteOverDirectTcp",
                        displayName: "Client facade rejects missing metadata queries and non-empty directory delete requests over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", System.Text.Encoding.UTF8.GetBytes("negative-facade-data"), token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.GetMetadataAsync("public", "docs\\missing.txt", token),
                                    "Expected metadata queries for missing paths to fail.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.DeleteAsync("public", "docs", token),
                                    "Expected delete requests for non-empty directories to fail.");

                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected a failed non-empty directory delete to preserve the child file.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected a failed non-empty directory delete to preserve the directory.");
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

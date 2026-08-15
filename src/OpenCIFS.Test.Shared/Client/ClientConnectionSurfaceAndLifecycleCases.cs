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
    internal static class ClientConnectionSurfaceAndLifecycleCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionAndSessionSurfacesDoNotExposePreviewMarkers",
                        displayName: "Client connection and session surfaces do not expose preview markers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsPreviewAttribute? connectionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientConnection), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? sessionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientSession), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (connectionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the managed direct-TCP client connection surface to remain outside preview-only markers.");
                            }

                            if (sessionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the low-level client session surface to remain outside preview-only markers.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionAdvancedSurfaceExposesTryAsyncResultEnvelopeCompanions",
                        displayName: "Client connection advanced surface exposes TryAsync result-envelope companions for lifecycle and raw SMB workflows",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            if (typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryConnectAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryConnectAndAuthenticateAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryTreeConnectAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryValidateSecureNegotiateAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryCompoundOpenReadCloseAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryOpenAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryReadAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryQueryDirectoryAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryChangeNotifyAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryCloseAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryDisconnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected the advanced/raw client connection surface to expose bounded Try...Async result-envelope companions.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionConnectsOverDirectTcpAndHandlesLowLevelOperations",
                        displayName: "Client connection connects over direct TCP and handles authenticated tree, open, read, write, query, set, rename, enumerate, delete, and close operations",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await client.ConnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(client.IsConnected, "Expected the client connection to own an active direct-TCP transport after connect.");
                                TestAssertions.True(client.Session.IsNegotiated, "Expected connect to complete SMB2 negotiation.");

                                await client.AuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(client.IsAuthenticated, "Expected authenticate to complete the SMB2 session setup flow.");

                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.Equal("public", treeHandle.ShareName, "Unexpected connected share name.");

                                OpenCifsClientOpenHandle directoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(directoryHandle.IsClosed, "Expected directory close to retire the tracked open handle.");

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("connection-surface-data");
                                uint writtenCount = await client.WriteAsync(fileHandle, expectedBytes, 0, token).ConfigureAwait(false);
                                TestAssertions.Equal((uint)expectedBytes.Length, writtenCount, "Expected the low-level connection to acknowledge the full write length.");
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);

                                byte[] actualBytes = await client.ReadAsync(fileHandle, (uint)expectedBytes.Length, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the low-level connection to round-trip the file payload.");

                                FileNetworkOpenInformation metadataBeforeResize = FileNetworkOpenInformation.ReadFrom(await client.QueryInfoAsync(
                                    fileHandle,
                                    FileInformationClass.NetworkOpenInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.Equal((ulong)expectedBytes.Length, metadataBeforeResize.EndOfFile, "Unexpected low-level EOF size before resize.");

                                await client.SetEndOfFileAsync(fileHandle, 6, token).ConfigureAwait(false);
                                FileNetworkOpenInformation metadataAfterResize = FileNetworkOpenInformation.ReadFrom(await client.QueryInfoAsync(
                                    fileHandle,
                                    FileInformationClass.NetworkOpenInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.Equal(6UL, metadataAfterResize.EndOfFile, "Expected the low-level connection EOF mutation to update file length.");

                                await client.SetRenameAsync(fileHandle, "docs\\renamed.txt", cancellationToken: token).ConfigureAwait(false);

                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(fileHandle.IsClosed, "Expected file close to retire the tracked open handle.");

                                OpenCifsClientOpenHandle enumerationHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] enumerationBuffer = await client.QueryDirectoryAsync(
                                    enumerationHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*.txt",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] directoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the low-level connection to enumerate the created file.");
                                TestAssertions.Equal("renamed.txt", directoryEntries[0].FileName, "Unexpected low-level directory entry name after rename.");
                                TestAssertions.Equal(6UL, directoryEntries[0].EndOfFile, "Expected directory enumeration to reflect the resized EOF.");
                                await client.CloseAsync(enumerationHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle deleteFileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\renamed.txt",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.SetDeletePendingAsync(deleteFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(deleteFileHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle emptyEnumerationHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] emptyEnumerationBuffer = await client.QueryDirectoryAsync(
                                    emptyEnumerationHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] emptyDirectoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(emptyEnumerationBuffer);
                                TestAssertions.Equal(0, emptyDirectoryEntries.Length, "Expected the low-level connection to leave the directory empty after deleting the renamed file.");
                                await client.CloseAsync(emptyEnumerationHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle deleteDirectoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.SetDeletePendingAsync(deleteDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(deleteDirectoryHandle, cancellationToken: token).ConfigureAwait(false);

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.True(treeHandle.IsDisconnected, "Expected tree disconnect to retire the tracked tree handle.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "docs", "renamed.txt")), "Expected low-level delete-pending to remove the renamed file from the backing share.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected low-level delete-pending to remove the emptied directory from the backing share.");
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
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionAutoValidatesSecureNegotiateDuringEncryptedSmb302TreeConnect",
                        displayName: "Client connection auto-validates secure negotiate during encrypted SMB 3.0.2 tree connect and supports explicit revalidation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnectionSecureNegotiate_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                minimumDialect: SmbDialect.Smb302,
                                maximumDialect: SmbDialect.Smb302,
                                requireEncryptionForSmb3: true).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    PreferEncryption = true
                                });

                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.Equal(SmbDialect.Smb302, client.Session.NegotiatedDialect!.Value, "Expected the direct-TCP secure-negotiate test client to negotiate SMB 3.0.2.");
                                TestAssertions.False(client.Session.IsSecureNegotiateValidated, "Expected secure-negotiate validation to remain pending until the first tree connection completes.");

                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(client.Session.IsSecureNegotiateValidated, "Expected SMB 3.0.2 tree connect to complete bounded secure-negotiate validation automatically.");

                                await client.ValidateSecureNegotiateAsync(treeHandle, token).ConfigureAwait(false);
                                OpenCifsClientResult validationResult = await client.TryValidateSecureNegotiateAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.True(validationResult.IsSuccess, "Expected the non-throwing explicit secure-negotiate validation path to succeed after the automatic tree-connect validation.");

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "secure.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("secure-negotiate-data");
                                await client.WriteAsync(fileHandle, expectedBytes, 0, token).ConfigureAwait(false);
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAsync(fileHandle, (uint)expectedBytes.Length, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the SMB 3.0.2 direct-TCP client to remain usable after automatic and explicit secure-negotiate validation.");

                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
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
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsUnauthenticatedUseBadCredentialsAndStaleHandles",
                        displayName: "Client connection rejects unauthenticated use, bad credentials, and stale handles",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            await using OpenCifsClientConnection disconnectedClient = new OpenCifsClientConnection(new OpenCifsClientOptions());
                            await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                () => disconnectedClient.AuthenticateAsync(CreateCredential(), token),
                                "Expected authenticate to reject use before connect.");
                            await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                () => disconnectedClient.TreeConnectAsync("public", token),
                                "Expected tree connect to reject use before authentication.");

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection wrongPasswordClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await wrongPasswordClient.ConnectAsync(token).ConfigureAwait(false);
                                OpenCifsClientCredential wrongCredential = new OpenCifsClientCredential
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "WrongPassword!"
                                };

                                OpenCifsStatusException authenticationException;

                                try
                                {
                                    await wrongPasswordClient.AuthenticateAsync(wrongCredential, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected the low-level connection surface to reject invalid credentials.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    authenticationException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.SessionSetup, authenticationException.Command, "Expected invalid credentials to report the SessionSetup command.");
                                TestAssertions.Equal(NtStatus.AccessDenied, authenticationException.Status, "Expected invalid credentials to report STATUS_ACCESS_DENIED.");
                                TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, authenticationException.Category, "Expected invalid credentials to normalize to AccessDenied.");
                                TestAssertions.False(wrongPasswordClient.IsConnected, "Expected failed authentication to tear down the direct-TCP transport.");

                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle nonEmptyDirectoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetDeletePendingAsync(nonEmptyDirectoryHandle, cancellationToken: token),
                                    "Expected the low-level connection to reject delete-pending for non-empty directories.");
                                await client.CloseAsync(nonEmptyDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected a failed low-level non-empty directory delete to preserve the child file.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected a failed low-level non-empty directory delete to preserve the directory.");

                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => client.ReadAsync(fileHandle, 1, 0, cancellationToken: token),
                                    "Expected closed open handles to be rejected.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => client.OpenAsync(treeHandle, "docs\\other.txt", cancellationToken: token),
                                    "Expected disconnected tree handles to be rejected.");
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionTryAsyncCompanionsReportPositiveAndNegativeAdvancedFlows",
                        displayName: "Client connection TryAsync companions report positive and negative advanced lifecycle and compound flows",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnectionTry_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "sample.txt"), "advanced-try-surface");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                OpenCifsClientResult connectAndAuthenticateResult = await client.TryConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(connectAndAuthenticateResult.IsSuccess, "Expected TryConnectAndAuthenticateAsync to succeed against the live listener.");

                                OpenCifsClientResult<OpenCifsClientTreeHandle> treeResult = await client.TryTreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(treeResult.IsSuccess, "Expected TryTreeConnectAsync to succeed for the public share.");
                                OpenCifsClientTreeHandle treeHandle = treeResult.GetValueOrThrow();

                                OpenCifsClientResult<byte[]> compoundReadResult = await client.TryCompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    64,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(compoundReadResult.IsSuccess, "Expected TryCompoundOpenReadCloseAsync to succeed for the existing file.");
                                TestAssertions.Equal("advanced-try-surface", System.Text.Encoding.UTF8.GetString(compoundReadResult.GetValueOrThrow()), "Expected the advanced/raw Try compound read to preserve the file payload.");

                                OpenCifsClientResult<byte[]> missingReadResult = await client.TryCompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\missing.txt",
                                    16,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(missingReadResult.IsSuccess, "Expected TryCompoundOpenReadCloseAsync to report a failure envelope for a missing file.");
                                TestAssertions.Equal(Smb2Command.Create, missingReadResult.Command, "Expected missing-file compound reads to surface the create leg.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadResult.Status, "Expected missing-file compound reads to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingReadResult.ErrorCategory, "Expected missing-file compound reads to normalize to NotFound.");

                                await TestAssertions.ThrowsAsync<ArgumentNullException>(
                                    () => client.TryOpenAsync(treeHandle: null!, path: "docs\\sample.txt", cancellationToken: token),
                                    "Expected advanced/raw Try wrappers to preserve local argument validation and not flatten it into a result envelope.");

                                OpenCifsClientResult disconnectResult = await client.TryDisconnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(disconnectResult.IsSuccess, "Expected TryDisconnectAsync to succeed after the live advanced/raw flow.");

                                OpenCifsClientResult<OpenCifsClientTreeHandle> postDisconnectTreeResult = await client.TryTreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.False(postDisconnectTreeResult.IsSuccess, "Expected TryTreeConnectAsync to report a failure envelope after disconnect.");
                                TestAssertions.True(postDisconnectTreeResult.Exception is OpenCifsClientStateException, "Expected post-disconnect advanced/raw failures to preserve the typed client-state exception.");
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
            };
        }
    }
}

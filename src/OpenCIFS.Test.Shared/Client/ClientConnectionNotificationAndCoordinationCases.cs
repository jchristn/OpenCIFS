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
    internal static class ClientConnectionNotificationAndCoordinationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesChangeNotifyOverDirectTcp",
                        displayName: "Client connection completes CHANGE_NOTIFY over direct TCP for nested watched-tree file creation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                notifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: true,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle childFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\nested\\child.txt",
                                    createDisposition: Smb2CreateDisposition.Create,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(childFileHandle, cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] entries = await notifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, entries.Length, "Expected CHANGE_NOTIFY to complete with a single nested file-create entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected nested file creation to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("nested\\child.txt", entries[0].FileName, "Expected watched-tree CHANGE_NOTIFY to return a nested relative path.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterNotify = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterNotify.Length, "Expected the watched directory to contain the nested directory after CHANGE_NOTIFY completion.");
                                TestAssertions.Equal("nested", entriesAfterNotify[0].FileName, "Unexpected watched-directory entry after CHANGE_NOTIFY completion.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionCompletesRenameAndDeleteChangeNotifyOverDirectTcp",
                        displayName: "Client connection completes CHANGE_NOTIFY over direct TCP for same-directory rename and delete",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle actorFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource renameNotifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                renameNotifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> renameNotifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: renameNotifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetRenameAsync(actorFileHandle, "watched\\renamed.txt", cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] renameEntries = await renameNotifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(2, renameEntries.Length, "Expected same-directory rename CHANGE_NOTIFY to return old and new name entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename entry to keep the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename entry to keep the renamed relative file name.");

                                using CancellationTokenSource deleteNotifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                deleteNotifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> deleteNotifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: deleteNotifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetDeletePendingAsync(actorFileHandle, deletePending: true, cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(actorFileHandle, cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] deleteEntries = await deleteNotifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected delete CHANGE_NOTIFY to return a single remove entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected delete CHANGE_NOTIFY to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected delete CHANGE_NOTIFY to retain the renamed relative file name.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionCancelsChangeNotifyForNonMatchingEventsOverDirectTcp",
                        displayName: "Client connection keeps CHANGE_NOTIFY pending for non-matching events and cancels it over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle actorFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\sample.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.SetEndOfFileAsync(actorFileHandle, 2, token).ConfigureAwait(false);
                                await actorClient.CloseAsync(actorFileHandle, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a size-only mutation to leave a filename-only CHANGE_NOTIFY request pending.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterCancel = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterCancel.Length, "Expected the watched directory to remain queryable after cancelling CHANGE_NOTIFY.");
                                TestAssertions.Equal("sample.txt", entriesAfterCancel[0].FileName, "Unexpected watched-directory entry after cancelling CHANGE_NOTIFY.");
                                TestAssertions.Equal(2UL, entriesAfterCancel[0].EndOfFile, "Expected the non-matching size mutation to persist after cancelling CHANGE_NOTIFY.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionCancelsNonRecursiveChangeNotifyForNestedCreateOverDirectTcp",
                        displayName: "Client connection keeps non-recursive CHANGE_NOTIFY pending for nested creates and cancels it over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle childFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\nested\\child.txt",
                                    createDisposition: Smb2CreateDisposition.Create,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(childFileHandle, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a non-recursive CHANGE_NOTIFY request to remain pending for nested creates.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending non-recursive CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterCancel = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterCancel.Length, "Expected the watched directory to remain queryable after cancelling the non-recursive CHANGE_NOTIFY request.");
                                TestAssertions.Equal("nested", entriesAfterCancel[0].FileName, "Unexpected watched-directory entry after cancelling the non-recursive CHANGE_NOTIFY request.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionHonorsSharedReadAccessAcrossDirectTcpSessions",
                        displayName: "Client connection honors shared read access across direct TCP sessions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "shared.txt"), "shared-read-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle secondOpen = await secondClient.OpenAsync(
                                    secondTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                byte[] sharedBytes = await secondClient.ReadAsync(secondOpen, 64, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(System.Text.Encoding.UTF8.GetBytes("shared-read-data"), sharedBytes, "Expected the second direct-TCP client to read through a shared-read open.");

                                await secondClient.CloseAsync(secondOpen, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionRejectsConflictingShareAccessAcrossDirectTcpSessions",
                        displayName: "Client connection rejects conflicting share access across direct TCP sessions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "shared.txt"), "shared-read-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException shareAccessException;

                                try
                                {
                                    await secondClient.OpenAsync(
                                        secondTree,
                                        "docs\\shared.txt",
                                        desiredAccess: 0x40000000U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected a direct-TCP write open to be rejected when another session only shares the file for reads.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    shareAccessException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, shareAccessException.Command, "Expected the direct-TCP share-access failure to report the Create command.");
                                TestAssertions.Equal(NtStatus.SharingViolation, shareAccessException.Status, "Expected the direct-TCP share-access failure to report STATUS_SHARING_VIOLATION.");
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, shareAccessException.Category, "Expected the direct-TCP share-access failure to normalize to Conflict.");

                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionAppliesByteRangeLocksOverDirectTcp",
                        displayName: "Client connection applies byte-range locks and unlocks over direct TCP",
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
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.WriteAsync(fileHandle, System.Text.Encoding.UTF8.GetBytes("lock-surface-data"), 0, token).ConfigureAwait(false);
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);

                                Smb2LockElement lockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                };
                                await client.LockAsync(fileHandle, new[] { lockElement }, token).ConfigureAwait(false);

                                Smb2LockElement unlockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                };
                                await client.LockAsync(fileHandle, new[] { unlockElement }, token).ConfigureAwait(false);
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
                        })
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsConflictingByteRangeLocksOverDirectTcp",
                        displayName: "Client connection rejects conflicting byte-range locks over direct TCP",
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
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle firstFileHandle = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await firstClient.WriteAsync(firstFileHandle, System.Text.Encoding.UTF8.GetBytes("lock-conflict-data"), 0, token).ConfigureAwait(false);
                                await firstClient.FlushAsync(firstFileHandle, token).ConfigureAwait(false);

                                Smb2LockElement exclusiveLockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                };
                                await firstClient.LockAsync(firstFileHandle, new[] { exclusiveLockElement }, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle secondFileHandle = await secondClient.OpenAsync(
                                    secondTree,
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException lockException;

                                try
                                {
                                    await secondClient.LockAsync(secondFileHandle, new[] { exclusiveLockElement }, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected a conflicting byte-range lock to be rejected across direct-TCP sessions.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    lockException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Lock, lockException.Command, "Expected the conflicting byte-range lock to report the Lock command.");
                                TestAssertions.Equal(NtStatus.LockNotGranted, lockException.Status, "Expected the conflicting byte-range lock to report STATUS_LOCK_NOT_GRANTED.");
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, lockException.Category, "Expected the conflicting byte-range lock to normalize to Conflict.");

                                Smb2LockElement unlockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                };
                                await firstClient.LockAsync(firstFileHandle, new[] { unlockElement }, token).ConfigureAwait(false);
                                await secondClient.CloseAsync(secondFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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
                        caseId: "ClientConnectionRejectsNonEmptyDirectoryDeleteWithExplicitStatus",
                        displayName: "Client connection reports explicit SMB status for non-empty directory delete rejection",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "nested", "child.txt"), "child");
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
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await client.OpenExistingPathAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException deleteException;

                                try
                                {
                                    await client.SetDeletePendingAsync(directoryHandle, true, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected non-empty directory delete-pending to be rejected.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    deleteException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.SetInfo, deleteException.Command, "Expected non-empty directory delete rejection to report the SetInfo command.");
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, deleteException.Status, "Expected non-empty directory delete rejection to report STATUS_DIRECTORY_NOT_EMPTY.");
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, deleteException.Category, "Expected non-empty directory delete rejection to normalize to Conflict.");
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);
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
            };
        }
    }
}

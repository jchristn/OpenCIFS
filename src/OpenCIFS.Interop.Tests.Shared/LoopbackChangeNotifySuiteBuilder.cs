namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class LoopbackChangeNotifySuiteBuilder
    {
        internal static TestSuiteDescriptor LoopbackChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackChangeNotify",
                displayName: "Loopback CHANGE_NOTIFY coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncChangeNotifyForCreate",
                        displayName: "Client and server loopback complete an async CHANGE_NOTIFY request for a created child file",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the loopback client to keep the async CHANGE_NOTIFY request pending after the interim response.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? finalResponse) && finalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response.");
                                client.ApplyResponseHeader(finalResponse!.Header);
                                FileNotifyInformation[] entries = client.ApplyChangeNotifyResult(
                                    notifyRequest,
                                    finalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload));
                                TestAssertions.Equal(1, entries.Length, "Expected the loopback CHANGE_NOTIFY completion to return a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected the created child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child.txt", entries[0].FileName, "Expected the created child file name to remain relative to the watched directory.");
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected the final async CHANGE_NOTIFY response to complete the pending client request.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncWatchTreeChangeNotifyForNestedCreate",
                        displayName: "Client and server loopback complete a watched-tree async CHANGE_NOTIFY request for a nested child file",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: true,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\nested\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\nested\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? finalResponse) && finalResponse != null, "Expected the server to emit a watched-tree final async CHANGE_NOTIFY response.");
                                client.ApplyResponseHeader(finalResponse!.Header);
                                FileNotifyInformation[] entries = client.ApplyChangeNotifyResult(
                                    notifyRequest,
                                    finalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload));
                                TestAssertions.Equal(1, entries.Length, "Expected the watched-tree CHANGE_NOTIFY completion to return a single nested notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected the nested child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("nested\\child.txt", entries[0].FileName, "Expected the watched-tree child path to remain relative to the watched directory.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncChangeNotifyForRenameAndDelete",
                        displayName: "Client and server loopback complete async CHANGE_NOTIFY requests for same-directory rename and delete",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header fileOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest fileOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(fileOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(sessionId, treeId, fileOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileOpenHeader, fileOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched\\sample.txt", fileOpenResult.Status, fileOpenResult.Response);

                                Smb2Header renameNotifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest renameNotifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse renameInterimResponse = server.HandleChangeNotify(renameNotifyHeader, renameNotifyRequest);
                                client.ApplyResponseHeader(renameInterimResponse.Header);

                                Smb2Header renameHeader = client.CreateRequestHeader(Smb2Command.SetInfo, treeId, sessionId: sessionId);
                                Smb2SetInfoRequest renameRequest = client.CreateSetRenameInfoRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    "watched\\renamed.txt");
                                server.ValidateAndAcceptRequestHeader(renameHeader, Smb2Command.SetInfo, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = server.HandleSetInfo(sessionId, treeId, renameRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(renameHeader, renameResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplySetRenameInfoResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, renameResult.Status, renameResult.Response, "watched\\renamed.txt");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? renameFinalResponse) && renameFinalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response for the rename.");
                                client.ApplyResponseHeader(renameFinalResponse!.Header);
                                FileNotifyInformation[] renameEntries = client.ApplyChangeNotifyResult(
                                    renameNotifyRequest,
                                    renameFinalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(renameFinalResponse.Payload));
                                TestAssertions.Equal(2, renameEntries.Length, "Expected the rename CHANGE_NOTIFY completion to return old and new name entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename notify entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename notify entry to retain the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename notify entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename notify entry to retain the renamed relative file name.");

                                Smb2Header deleteNotifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest deleteNotifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse deleteInterimResponse = server.HandleChangeNotify(deleteNotifyHeader, deleteNotifyRequest);
                                client.ApplyResponseHeader(deleteInterimResponse.Header);

                                Smb2Header dispositionHeader = client.CreateRequestHeader(Smb2Command.SetInfo, treeId, sessionId: sessionId);
                                Smb2SetInfoRequest dispositionRequest = client.CreateSetDispositionInfoRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    deletePending: true);
                                server.ValidateAndAcceptRequestHeader(dispositionHeader, Smb2Command.SetInfo, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = server.HandleSetInfo(sessionId, treeId, dispositionRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(dispositionHeader, dispositionResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplySetDispositionInfoResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, dispositionResult.Status, dispositionResult.Response, deletePending: true);

                                Smb2Header fileCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest fileCloseRequest = client.CreateCloseRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(fileCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(sessionId, treeId, fileCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileCloseHeader, fileCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? deleteFinalResponse) && deleteFinalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response for the delete.");
                                client.ApplyResponseHeader(deleteFinalResponse!.Header);
                                FileNotifyInformation[] deleteEntries = client.ApplyChangeNotifyResult(
                                    deleteNotifyRequest,
                                    deleteFinalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(deleteFinalResponse.Payload));
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected the delete CHANGE_NOTIFY completion to return a single remove entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected the delete notify entry to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected the delete notify entry to retain the renamed relative file name.");

                                Smb2Header directoryCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest directoryCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(directoryCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(sessionId, treeId, directoryCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryCloseHeader, directoryCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCancelAsyncChangeNotifyRequest",
                        displayName: "Client and server loopback cancel an async CHANGE_NOTIFY request",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected loopback async cancel handling to cancel the pending CHANGE_NOTIFY request.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected the cancelled loopback CHANGE_NOTIFY request to leave no pending client request state.");

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerKeepChangeNotifyPendingForNonMatchingFiltersUntilCancel",
                        displayName: "Client and server loopback keep CHANGE_NOTIFY pending for non-matching filters until cancel",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header fileOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest fileOpenRequest = client.CreateCreateRequest(treeId, "watched\\sample.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(fileOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(sessionId, treeId, fileOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileOpenHeader, fileOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched\\sample.txt", fileOpenResult.Status, fileOpenResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the loopback CHANGE_NOTIFY request to remain pending after the interim response.");

                                Smb2Header writeHeader = client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: sessionId);
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, new byte[] { 0x41, 0x42 }, 0);
                                server.ValidateAndAcceptRequestHeader(writeHeader, Smb2Command.Write, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(sessionId, treeId, writeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(writeHeader, writeResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyWriteResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, writeResult.Status, writeResult.Response);

                                TestAssertions.False(server.TryDequeueAsyncResponse(out _), "Expected a filename-only CHANGE_NOTIFY request to remain pending after a size-only write mutation.");
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the non-matching change to leave the loopback CHANGE_NOTIFY request pending.");

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected the loopback non-matching CHANGE_NOTIFY request to be cancellable.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected cancelling the non-matching loopback CHANGE_NOTIFY request to clear pending client state.");

                                Smb2Header fileCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest fileCloseRequest = client.CreateCloseRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(fileCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(sessionId, treeId, fileCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileCloseHeader, fileCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerKeepNonRecursiveChangeNotifyPendingForNestedCreateUntilCancel",
                        displayName: "Client and server loopback keep a non-recursive CHANGE_NOTIFY pending for nested creates until cancel",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the non-recursive CHANGE_NOTIFY request to remain pending after the interim response.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\nested\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\nested\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.False(server.TryDequeueAsyncResponse(out _), "Expected a non-recursive CHANGE_NOTIFY request to remain pending for nested creates.");
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the nested create to leave the non-recursive CHANGE_NOTIFY request pending.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected the pending non-recursive CHANGE_NOTIFY request to be cancellable.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected cancelling the non-recursive CHANGE_NOTIFY request to clear pending client state.");

                                Smb2Header directoryCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest directoryCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(directoryCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(sessionId, treeId, directoryCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryCloseHeader, directoryCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerRejectChangeNotifyOnNonDirectoryOpen",
                        displayName: "Client and server loopback reject CHANGE_NOTIFY on a non-directory open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "watched.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 3);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(treeId, "watched.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched.txt", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 128);
                                OpenCifsServerAsyncResponse finalResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);

                                client.ApplyResponseHeader(finalResponse.Header);
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyChangeNotifyResult(notifyRequest, finalResponse.Header.Status, Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload)),
                                    "Expected loopback CHANGE_NOTIFY coverage to reject file opens that are not directories.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }
    }
}

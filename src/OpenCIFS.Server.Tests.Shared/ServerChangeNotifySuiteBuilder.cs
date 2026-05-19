namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Sample.OpenCifsServer;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;
    internal static class ServerChangeNotifySuiteBuilder
    {
        internal static TestSuiteDescriptor ServerChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.ChangeNotify",
                displayName: "Server CHANGE_NOTIFY handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerReturnsInterimPendingAndCancelsAsyncChangeNotifyRequests",
                        displayName: "Server returns interim async pending headers and cancels pending CHANGE_NOTIFY requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected opening the watched directory to succeed.");

                                Smb2Header notifyHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId);
                                OpenCifsServerAsyncResponse interimResponse = host.HandleChangeNotify(
                                    notifyHeader,
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });

                                TestAssertions.Equal(NtStatus.Pending, interimResponse.Header.Status, "Expected CHANGE_NOTIFY to enter async pending state.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand, interimResponse.Header.Flags, "Expected interim CHANGE_NOTIFY responses to carry the async flag.");
                                TestAssertions.Equal((ushort)3, interimResponse.Header.CreditRequest, "Expected the interim CHANGE_NOTIFY response to replenish the requested credits.");

                                OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                    CreateRequestHeader(
                                        Smb2Command.Cancel,
                                        messageId: notifyHeader.MessageId,
                                        creditRequest: 0,
                                        flags: Smb2HeaderFlags.AsyncCommand,
                                        sessionId: sessionId,
                                        asyncId: interimResponse.Header.AsyncId),
                                    new Smb2CancelRequest());

                                TestAssertions.True(cancelResult.WasCancelled, "Expected the pending CHANGE_NOTIFY request to be cancellable through the async cancel path.");
                                TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected async cancellation to emit a target response header.");
                                TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader!.Status, "Expected async cancellation to fail the pending CHANGE_NOTIFY request with STATUS_CANCELLED.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand, cancelResult.TargetResponseHeader.Flags, "Expected the cancelled CHANGE_NOTIFY target response to remain async.");
                                TestAssertions.Equal((ushort)0, cancelResult.TargetResponseHeader.CreditRequest, "Expected final async CHANGE_NOTIFY cancellations to avoid granting credits a second time.");
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
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerCompletesChangeNotifyRequestsForCreateAndOverflow",
                        displayName: "Server completes pending CHANGE_NOTIFY requests for create events and buffer overflow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected opening the watched directory to succeed.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2CreateResponse> createChildResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("watched\\child.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, createChildResult.Status, "Expected creating the child file to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? createdResponse) && createdResponse != null, "Expected the create event to complete the pending CHANGE_NOTIFY request.");
                                TestAssertions.Equal(NtStatus.Success, createdResponse!.Header.Status, "Expected the completed CHANGE_NOTIFY response to indicate success.");
                                FileNotifyInformation[] createdEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(createdResponse.Payload).OutputBuffer);
                                TestAssertions.Equal(1, createdEntries.Length, "Expected the create event to generate a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, createdEntries[0].Action, "Expected the created child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child.txt", createdEntries[0].FileName, "Expected the created child file name to be relative to the watched directory.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = createChildResult.Response.PersistentFileId,
                                            VolatileFileId = createChildResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the created child file to close cleanly after the notify event.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, creditRequest: 1, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 4,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2CreateResponse> overflowCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("watched\\second-child.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, overflowCreateResult.Status, "Expected the overflow child create to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? overflowResponse) && overflowResponse != null, "Expected the overflow create event to complete the pending CHANGE_NOTIFY request.");
                                TestAssertions.Equal(NtStatus.NotifyEnumDir, overflowResponse!.Header.Status, "Expected insufficient output buffers to surface as STATUS_NOTIFY_ENUM_DIR.");
                                TestAssertions.Equal(0, Smb2ChangeNotifyResponse.ReadFrom(overflowResponse.Payload).OutputBuffer.Length, "Expected STATUS_NOTIFY_ENUM_DIR responses to omit FILE_NOTIFY_INFORMATION entries.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = overflowCreateResult.Response.PersistentFileId,
                                            VolatileFileId = overflowCreateResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the overflow child file to close cleanly after the notify event.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = openResult.Response.PersistentFileId,
                                            VolatileFileId = openResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the watched directory open to close cleanly after the notify coverage.");
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
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerCompletesChangeNotifyRequestsForRenameDeleteAndMetadataMutations",
                        displayName: "Server completes pending CHANGE_NOTIFY requests for same-directory rename, metadata mutation, and delete events",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, directoryOpenResult.Status, "Expected opening the watched directory to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched\\sample.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpenResult.Status, "Expected opening the watched file to succeed.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "watched\\renamed.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renameResult.Status, "Expected the watched file rename to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? renameResponse) && renameResponse != null, "Expected the rename to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] renameEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(renameResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(2, renameEntries.Length, "Expected same-directory rename to surface old and new name notify entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename notify entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename notify entry to preserve the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename notify entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename notify entry to preserve the renamed relative file name.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, creditRequest: 2, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.Attributes | FileNotifyChangeFilter.LastWrite
                                    });
                                ulong expectedLastWriteTime = 133595680890000000UL;
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> basicInfoResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            LastWriteTime = expectedLastWriteTime,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, basicInfoResult.Status, "Expected the watched file basic-info mutation to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? basicInfoResponse) && basicInfoResponse != null, "Expected the metadata mutation to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] basicInfoEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(basicInfoResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(1, basicInfoEntries.Length, "Expected the metadata mutation to surface a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Modified, basicInfoEntries[0].Action, "Expected the metadata mutation to surface FILE_ACTION_MODIFIED.");
                                TestAssertions.Equal("renamed.txt", basicInfoEntries[0].FileName, "Expected the metadata mutation to preserve the renamed relative file name.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 2, creditRequest: 2, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionResult.Status, "Expected the watched file delete-pending mutation to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> deletedCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.None,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deletedCloseResult.Status, "Expected the delete-pending watched file to close cleanly.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? deleteResponse) && deleteResponse != null, "Expected the delete to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] deleteEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(deleteResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected the delete to surface a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected the delete to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected the delete to preserve the renamed relative file name.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.None,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryCloseResult.Status, "Expected the watched directory open to close cleanly after the extended notify coverage.");
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

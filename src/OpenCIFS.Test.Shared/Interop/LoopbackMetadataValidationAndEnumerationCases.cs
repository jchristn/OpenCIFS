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
    internal static class LoopbackMetadataValidationAndEnumerationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRejectInvalidIdentifiersAcrossMetadataSurface",
                        displayName: "Client and server loopback reject invalid session, tree, and open identifiers across the bounded metadata surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropMetadataIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "metadata.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "metadata.txt", desiredAccess: 0xC0010080U, createDisposition: Smb2CreateDisposition.Open));
                                OpenState fileOpen = client.ApplyCreateResult(treeId, "metadata.txt", fileOpenResult.Status, fileOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "folder", desiredAccess: 0x80000000U, createDisposition: Smb2CreateDisposition.Open, createOptions: Smb2CreateOptions.DirectoryFile));
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "folder", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2QueryInfoRequest queryInfoRequest = client.CreateQueryInfoRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId, FileInformationClass.BasicInformation);
                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> invalidQuerySessionResult = server.HandleQueryInfo(client.SessionId.Value + 1, treeId, queryInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidQuerySessionResult.Status, "Expected loopback query-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidQuerySessionResult.Status, invalidQuerySessionResult.Response),
                                    "Expected the client to surface invalid-session query-info failures.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> invalidQueryTreeResult = server.HandleQueryInfo(client.SessionId.Value, treeId + 1, queryInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidQueryTreeResult.Status, "Expected loopback query-info requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidQueryTreeResult.Status, invalidQueryTreeResult.Response),
                                    "Expected the client to surface invalid-tree query-info failures.");

                                Smb2SetInfoRequest setInfoRequest = client.CreateSetBasicInfoRequest(
                                    fileOpen.PersistentFileId,
                                    fileOpen.VolatileFileId,
                                    new FileBasicInformation
                                    {
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidSetSessionResult = server.HandleSetInfo(client.SessionId.Value + 1, treeId, setInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidSetSessionResult.Status, "Expected loopback set-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidSetSessionResult.Status, invalidSetSessionResult.Response),
                                    "Expected the client to surface invalid-session set-info failures.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidSetTreeResult = server.HandleSetInfo(client.SessionId.Value, treeId + 1, setInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidSetTreeResult.Status, "Expected loopback set-info requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidSetTreeResult.Status, invalidSetTreeResult.Response),
                                    "Expected the client to surface invalid-tree set-info failures.");

                                Smb2QueryDirectoryRequest queryDirectoryRequest = client.CreateQueryDirectoryRequest(
                                    directoryOpen.PersistentFileId,
                                    directoryOpen.VolatileFileId,
                                    FileInformationClass.DirectoryInformation,
                                    outputBufferLength: 512,
                                    fileNamePattern: "*",
                                    flags: Smb2QueryDirectoryFlags.RestartScans);
                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> invalidDirectorySessionResult = server.HandleQueryDirectory(client.SessionId.Value + 1, treeId, queryDirectoryRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidDirectorySessionResult.Status, "Expected loopback query-directory requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryDirectoryResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, invalidDirectorySessionResult.Status, invalidDirectorySessionResult.Response),
                                    "Expected the client to surface invalid-session query-directory failures.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> invalidDirectoryTreeResult = server.HandleQueryDirectory(client.SessionId.Value, treeId + 1, queryDirectoryRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidDirectoryTreeResult.Status, "Expected loopback query-directory requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryDirectoryResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, invalidDirectoryTreeResult.Status, invalidDirectoryTreeResult.Response),
                                    "Expected the client to surface invalid-tree query-directory failures.");

                                Smb2IoctlRequest ioctlRequest = client.CreateEnumerateSnapshotsRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId, maxOutputResponse: 128);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> invalidIoctlSessionResult = server.HandleIoctl(client.SessionId.Value + 1, treeId, ioctlRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidIoctlSessionResult.Status, "Expected loopback IOCTL requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyIoctlResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidIoctlSessionResult.Status, invalidIoctlSessionResult.Response),
                                    "Expected the client to surface invalid-session IOCTL failures.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> invalidIoctlTreeResult = server.HandleIoctl(client.SessionId.Value, treeId + 1, ioctlRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidIoctlTreeResult.Status, "Expected loopback IOCTL requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyIoctlResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidIoctlTreeResult.Status, invalidIoctlTreeResult.Response),
                                    "Expected the client to surface invalid-tree IOCTL failures.");

                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    directoryOpen.PersistentFileId,
                                    directoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    outputBufferLength: 512);
                                OpenCifsServerAsyncResponse invalidNotifySessionResult = server.HandleChangeNotify(
                                    client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: client.SessionId.Value + 1),
                                    notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifySessionResult.Header.Status, "Expected loopback change-notify requests with an unknown session identifier to be rejected.");
                                client.ApplyResponseHeader(invalidNotifySessionResult.Header);

                                OpenCifsServerAsyncResponse invalidNotifyTreeResult = server.HandleChangeNotify(
                                    client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId + 1, sessionId: client.SessionId.Value),
                                    notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifyTreeResult.Header.Status, "Expected loopback change-notify requests with an unknown tree identifier to be rejected.");
                                client.ApplyResponseHeader(invalidNotifyTreeResult.Header);

                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId));
                                client.ApplyCloseResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerEnumerateDirectoryEntries",
                        displayName: "Client and server loopback enumerate directory entries through bounded query-directory requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "alpha");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "beta.log"), "beta");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "folder",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "folder", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the loopback directory open.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> firstEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.DirectoryInformation,
                                        outputBufferLength: 512,
                                        fileNamePattern: "*",
                                        flags: Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry));
                                FileDirectoryInformationEntry[] firstEntries = FileDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, firstEnumerationResult.Status, firstEnumerationResult.Response));
                                TestAssertions.Equal(1, firstEntries.Length, "Expected the first loopback directory enumeration to honor ReturnSingleEntry.");
                                TestAssertions.Equal("alpha.txt", firstEntries[0].FileName, "Unexpected first loopback directory entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> resumedEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.DirectoryInformation,
                                        outputBufferLength: 4096));
                                FileDirectoryInformationEntry[] resumedEntries = FileDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, resumedEnumerationResult.Status, resumedEnumerationResult.Response));
                                TestAssertions.Equal(2, resumedEntries.Length, "Expected the resumed loopback directory enumeration to return the remaining entries.");
                                TestAssertions.Equal("beta.log", resumedEntries[0].FileName, "Unexpected second loopback directory entry.");
                                TestAssertions.Equal("nested", resumedEntries[1].FileName, "Unexpected final loopback directory entry.");
                                TestAssertions.True(
                                    (resumedEntries[1].FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0,
                                    "Expected loopback directory enumeration to preserve directory attributes.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> filteredEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.FullDirectoryInformation,
                                        outputBufferLength: 4096,
                                        fileNamePattern: "*.txt",
                                        flags: Smb2QueryDirectoryFlags.RestartScans));
                                FileFullDirectoryInformationEntry[] filteredEntries = FileFullDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, filteredEnumerationResult.Status, filteredEnumerationResult.Response));
                                TestAssertions.Equal(1, filteredEntries.Length, "Expected the filtered loopback directory enumeration to return a single matching entry.");
                                TestAssertions.Equal("alpha.txt", filteredEntries[0].FileName, "Unexpected filtered loopback directory entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> bothEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.BothDirectoryInformation,
                                        outputBufferLength: 4096,
                                        fileNamePattern: "*.log",
                                        flags: Smb2QueryDirectoryFlags.RestartScans));
                                FileBothDirectoryInformationEntry[] bothEntries = FileBothDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, bothEnumerationResult.Status, bothEnumerationResult.Response));
                                TestAssertions.Equal(1, bothEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION loopback enumeration to return a single filtered entry.");
                                TestAssertions.Equal("beta.log", bothEntries[0].FileName, "Unexpected FILE_BOTH_DIR_INFORMATION loopback entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> exhaustedEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.FullDirectoryInformation,
                                        outputBufferLength: 4096));
                                byte[] exhaustedEnumerationBytes = client.ApplyQueryDirectoryResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    exhaustedEnumerationResult.Status,
                                    exhaustedEnumerationResult.Response);
                                TestAssertions.Equal(0, exhaustedEnumerationBytes.Length, "Expected exhausted loopback directory enumeration to return an empty payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback directory open after close.");
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
            };
        }
    }
}

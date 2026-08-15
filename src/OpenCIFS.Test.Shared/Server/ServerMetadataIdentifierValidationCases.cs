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
    internal static class ServerMetadataIdentifierValidationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsInvalidSessionTreeAndOpenIdentifiersAcrossMetadataSurface",
                        displayName: "Server rejects invalid session, tree, and open identifiers across the bounded metadata surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerMetadataIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "metadata.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("metadata.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010080U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the metadata file test open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("folder", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U, createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the metadata directory test open to succeed.");

                                Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    OutputBufferLength = 512,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryInfo(sessionId + 1, treeId, queryInfoRequest).Status, "Expected query-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryInfo(sessionId, treeId + 1, queryInfoRequest).Status, "Expected query-info requests with an unknown tree identifier to be rejected.");

                                Smb2SetInfoRequest setInfoRequest = new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    Buffer = new FileBasicInformation
                                    {
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                    }.ToByteArray()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleSetInfo(sessionId + 1, treeId, setInfoRequest).Status, "Expected set-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleSetInfo(sessionId, treeId + 1, setInfoRequest).Status, "Expected set-info requests with an unknown tree identifier to be rejected.");

                                Smb2QueryDirectoryRequest queryDirectoryRequest = new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    Flags = Smb2QueryDirectoryFlags.RestartScans,
                                    PersistentFileId = directoryOpen.Response.PersistentFileId,
                                    VolatileFileId = directoryOpen.Response.VolatileFileId,
                                    OutputBufferLength = 512,
                                    FileNamePattern = "*"
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryDirectory(sessionId + 1, treeId, queryDirectoryRequest).Status, "Expected query-directory requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryDirectory(sessionId, treeId + 1, queryDirectoryRequest).Status, "Expected query-directory requests with an unknown tree identifier to be rejected.");

                                Smb2IoctlRequest ioctlRequest = new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    MaxInputResponse = 16,
                                    MaxOutputResponse = 128,
                                    Flags = Smb2IoctlFlags.IsFsctl,
                                    InputBuffer = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleIoctl(sessionId + 1, treeId, ioctlRequest).Status, "Expected IOCTL requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleIoctl(sessionId, treeId + 1, ioctlRequest).Status, "Expected IOCTL requests with an unknown tree identifier to be rejected.");

                                Smb2Header invalidNotifyHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, sessionId: sessionId + 1, treeId: treeId);
                                Smb2ChangeNotifyRequest notifyRequest = new Smb2ChangeNotifyRequest
                                {
                                    Flags = 0,
                                    OutputBufferLength = 512,
                                    PersistentFileId = directoryOpen.Response.PersistentFileId,
                                    VolatileFileId = directoryOpen.Response.VolatileFileId,
                                    CompletionFilter = FileNotifyChangeFilter.FileName
                                };
                                OpenCifsServerAsyncResponse invalidNotifySessionResponse = host.HandleChangeNotify(invalidNotifyHeader, notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifySessionResponse.Header.Status, "Expected change-notify requests with an unknown session identifier to be rejected.");

                                Smb2Header invalidNotifyTreeHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, sessionId: sessionId, treeId: treeId + 1);
                                OpenCifsServerAsyncResponse invalidNotifyTreeResponse = host.HandleChangeNotify(invalidNotifyTreeHeader, notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifyTreeResponse.Header.Status, "Expected change-notify requests with an unknown tree identifier to be rejected.");

                                TestAssertions.Equal(NtStatus.Success, host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId
                                    }).Status,
                                    "Expected the metadata file test open to close cleanly.");
                                TestAssertions.Equal(NtStatus.Success, host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    }).Status,
                                    "Expected the metadata directory test open to close cleanly.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        })
            };
        }
    }
}

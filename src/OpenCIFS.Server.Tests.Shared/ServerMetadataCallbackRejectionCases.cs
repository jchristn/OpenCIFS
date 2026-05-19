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
    internal static class ServerMetadataCallbackRejectionCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerMetadataCallbacksAllowTrackedOpensAndRejectSetInfoAndQueryDirectoryRequests",
                        displayName: "Server metadata callbacks allow tracked opens and reject selected set-info and query-directory requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsMetadataCallbacks_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "query.txt"), "seed");
                            int queryDirectoryCallbackCount = 0;
                            int setInfoCallbackCount = 0;

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(
                                    sharePath,
                                    new OpenCifsServerRequestCallbacks
                                    {
                                        QueryDirectoryCallback = context =>
                                        {
                                            queryDirectoryCallbackCount++;
                                            TestAssertions.Equal("public", context.ShareName, "Expected the query-directory callback to observe the resolved share name.");
                                            TestAssertions.Equal(Path.Combine(sharePath, "folder"), context.FullPath, "Expected the query-directory callback to observe the resolved directory path.");
                                            return NtStatus.AccessDenied;
                                        },
                                        SetInfoCallback = context =>
                                        {
                                            setInfoCallbackCount++;
                                            TestAssertions.Equal("public", context.ShareName, "Expected the set-info callback to observe the resolved share name.");
                                            TestAssertions.Equal(Path.Combine(sharePath, "query.txt"), context.FullPath, "Expected the set-info callback to observe the resolved file path.");

                                            if (context.Request.FileInfoClass == FileInformationClass.RenameInformation)
                                            {
                                                return NtStatus.NotSupported;
                                            }

                                            return null;
                                        }
                                    });

                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);

                                ulong sessionId = treeContext.SessionId;

                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory open to succeed before query-directory callback enforcement.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, queryDirectoryResult.Status, "Expected the query-directory callback to reject directory enumeration.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the callback-protected directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("query.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the file open to succeed before set-info callback enforcement.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "renamed.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, renameResult.Status, "Expected the set-info callback to reject the selected rename mutation.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> fileClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileClose.Status, "Expected the callback-protected file open to close cleanly.");

                                TestAssertions.Equal(1, queryDirectoryCallbackCount, "Expected the query-directory callback to run once.");
                                TestAssertions.Equal(1, setInfoCallbackCount, "Expected the set-info callback to run once for the selected rename request.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "query.txt")), "Expected the rejected rename to leave the original file in place.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "renamed.txt")), "Expected the rejected rename to avoid creating a renamed destination.");
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

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
    internal static class ServerMetadataDirectoryRenameCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRenamesDirectoriesAndRejectsRenameWhileSubtreeIsOpen",
                        displayName: "Server renames directories through bounded FILE_RENAME_INFORMATION and rejects rename while the subtree is open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "source"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "blocked-folder"));
                            File.WriteAllText(Path.Combine(sharePath, "source", "child.txt"), "seed");
                            File.WriteAllText(Path.Combine(sharePath, "blocked-folder", "open.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> childOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("source\\child.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, childOpen.Status, "Expected the child file open to succeed before the directory rename.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> childAllocationResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = childOpen.Response.PersistentFileId,
                                        VolatileFileId = childOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 128
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, childAllocationResult.Status, "Expected the child allocation update to succeed before the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> childClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = childOpen.Response.PersistentFileId,
                                        VolatileFileId = childOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, childClose.Status, "Expected the child file open to close cleanly before the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "source",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the source directory open to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> directoryRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "archive\\renamed-folder"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryRenameResult.Status, "Expected the bounded directory rename to succeed.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "source")), "Expected the source directory path to be removed after rename.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "archive", "renamed-folder")), "Expected the renamed directory path to exist after rename.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "archive", "renamed-folder", "child.txt")), "Expected child files to move with the renamed directory.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedDirectoryNameResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NameInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renamedDirectoryNameResult.Status, "Expected FILE_NAME_INFORMATION on the renamed directory open to succeed.");
                                FileNameInformation renamedDirectoryName = FileNameInformation.ReadFrom(renamedDirectoryNameResult.Response.OutputBuffer);
                                TestAssertions.Equal("archive\\renamed-folder", renamedDirectoryName.FileName, "Unexpected FILE_NAME_INFORMATION path after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> movedChildOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("archive\\renamed-folder\\child.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, movedChildOpen.Status, "Expected opening the moved child file to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> movedChildStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = movedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = movedChildOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, movedChildStandardResult.Status, "Expected FILE_STANDARD_INFORMATION on the moved child file to succeed.");
                                FileStandardInformation movedChildStandardInformation = FileStandardInformation.ReadFrom(movedChildStandardResult.Response.OutputBuffer);
                                TestAssertions.Equal(128UL, movedChildStandardInformation.AllocationSize, "Expected declared allocation state to move with the renamed directory subtree.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> movedChildClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = movedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = movedChildOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, movedChildClose.Status, "Expected the moved child file open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> oldPathOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("source\\child.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, oldPathOpen.Status, "Expected the old child path to disappear after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the renamed directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "blocked-folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, blockedDirectoryOpen.Status, "Expected the blocked-directory open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedChildOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("blocked-folder\\open.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, blockedChildOpen.Status, "Expected the child open inside the blocked directory to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> blockedRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = blockedDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "archive\\blocked-renamed"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, blockedRenameResult.Status, "Expected directory renames with tracked subtree opens to be rejected.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "blocked-folder")), "Expected the blocked directory path to remain after the rejected rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> blockedChildClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = blockedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedChildOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, blockedChildClose.Status, "Expected the blocked child open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> blockedDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = blockedDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, blockedDirectoryClose.Status, "Expected the blocked directory open to close cleanly.");
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

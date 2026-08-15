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
    internal static class ServerFileIoCreationAndOverwriteCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerCreatesDirectoriesForCreateAndOpenIf",
                        displayName: "Server creates directories for bounded SMB2 directory create dispositions and reports collisions cleanly",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-directory"));
                            File.WriteAllText(Path.Combine(sharePath, "existing-file.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> createDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "created-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, createDirectoryResult.Status, "Expected FILE_CREATE on a missing directory path to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, createDirectoryResult.Response.CreateAction, "Expected FILE_CREATE on a missing directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "created-directory")), "Expected the backing directory to be created.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> createDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = createDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = createDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, createDirectoryClose.Status, "Expected the created-directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> openIfCreateDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "openif-directory",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openIfCreateDirectoryResult.Status, "Expected FILE_OPEN_IF on a missing directory path to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, openIfCreateDirectoryResult.Response.CreateAction, "Expected FILE_OPEN_IF on a missing directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "openif-directory")), "Expected FILE_OPEN_IF to create the missing backing directory.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> openIfCreateDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = openIfCreateDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = openIfCreateDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, openIfCreateDirectoryClose.Status, "Expected the FILE_OPEN_IF-created directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> existingOpenIfDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, existingOpenIfDirectoryResult.Status, "Expected FILE_OPEN_IF on an existing directory to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Opened, existingOpenIfDirectoryResult.Response.CreateAction, "Expected FILE_OPEN_IF on an existing directory to report Opened.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> existingOpenIfDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = existingOpenIfDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = existingOpenIfDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, existingOpenIfDirectoryClose.Status, "Expected the existing-directory FILE_OPEN_IF open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> plainExistingDirectoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.None,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, plainExistingDirectoryOpenResult.Status, "Expected Windows-style plain opens of existing directories to succeed when FILE_NON_DIRECTORY_FILE is not requested.");
                                TestAssertions.Equal(Smb2CreateAction.Opened, plainExistingDirectoryOpenResult.Response.CreateAction, "Expected plain opens of existing directories to report Opened.");
                                TestAssertions.True((plainExistingDirectoryOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected plain opens of existing directories to resolve to directory metadata.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> plainExistingDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = plainExistingDirectoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = plainExistingDirectoryOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, plainExistingDirectoryClose.Status, "Expected the Windows-style plain directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> nonDirectoryExistingDirectoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Normal));
                                TestAssertions.Equal(NtStatus.FileIsADirectory, nonDirectoryExistingDirectoryOpenResult.Status, "Expected explicit FILE_NON_DIRECTORY_FILE opens against an existing directory to remain rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryCollisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, directoryCollisionResult.Status, "Expected FILE_CREATE on an existing directory to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileCollisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-file.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, fileCollisionResult.Status, "Expected FILE_CREATE against an existing file through FILE_DIRECTORY_FILE to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> notDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-file.txt",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.NotADirectory, notDirectoryResult.Status, "Expected non-CREATE directory opens against an existing file to report STATUS_NOT_A_DIRECTORY.");
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
                        suiteId: "Server.FileIo",
                        caseId: "ServerHonorsSupersedeOverwriteAndOverwriteIf",
                        displayName: "Server honors bounded file supersede and overwrite create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite.txt"), "seed overwrite");
                            File.WriteAllText(Path.Combine(sharePath, "supersede.txt"), "seed supersede");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> seededOverwriteOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U));
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteOpen.Status, "Expected the seed overwrite open to succeed.");
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seededOverwriteAllocation = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = seededOverwriteOpen.Response.PersistentFileId,
                                        VolatileFileId = seededOverwriteOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 64
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteAllocation.Status, "Expected the seed overwrite allocation update to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> seededOverwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = seededOverwriteOpen.Response.PersistentFileId,
                                        VolatileFileId = seededOverwriteOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteClose.Status, "Expected the seed overwrite open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite.txt", Smb2CreateDisposition.Overwrite, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.Success, overwriteResult.Status, "Expected FILE_OVERWRITE on an existing file to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, overwriteResult.Response.CreateAction, "Expected FILE_OVERWRITE on an existing file to report Overwritten.");
                                TestAssertions.Equal(0UL, overwriteResult.Response.EndOfFile, "Expected FILE_OVERWRITE to truncate the existing file.");
                                TestAssertions.Equal(0UL, overwriteResult.Response.AllocationSize, "Expected FILE_OVERWRITE to reset declared allocation state after truncation.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = overwriteResult.Response.PersistentFileId,
                                        VolatileFileId = overwriteResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, overwriteClose.Status, "Expected the overwritten file open to close cleanly.");
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "overwrite.txt")).Length, "Expected FILE_OVERWRITE to leave the backing file truncated.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingOverwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing-overwrite.txt", Smb2CreateDisposition.Overwrite, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingOverwriteResult.Status, "Expected FILE_OVERWRITE on a missing file to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfMissingResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite-if-created.txt", Smb2CreateDisposition.OverwriteIf, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.Success, overwriteIfMissingResult.Status, "Expected FILE_OVERWRITE_IF on a missing file to create the file.");
                                TestAssertions.Equal(Smb2CreateAction.Created, overwriteIfMissingResult.Response.CreateAction, "Expected FILE_OVERWRITE_IF on a missing file to report Created.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteIfMissingClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = overwriteIfMissingResult.Response.PersistentFileId,
                                        VolatileFileId = overwriteIfMissingResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, overwriteIfMissingClose.Status, "Expected the created overwrite-if file to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> seededSupersedeOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("supersede.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U));
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeOpen.Status, "Expected the seed supersede open to succeed.");
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seededSupersedeAllocation = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = seededSupersedeOpen.Response.PersistentFileId,
                                        VolatileFileId = seededSupersedeOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 96
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeAllocation.Status, "Expected the seed supersede allocation update to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> seededSupersedeClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = seededSupersedeOpen.Response.PersistentFileId,
                                        VolatileFileId = seededSupersedeOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeClose.Status, "Expected the seed supersede open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> supersedeResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("supersede.txt", Smb2CreateDisposition.Supersede, desiredAccess: 0xC0010000U));
                                TestAssertions.Equal(NtStatus.Success, supersedeResult.Status, "Expected FILE_SUPERSEDE on an existing file to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Superseded, supersedeResult.Response.CreateAction, "Expected FILE_SUPERSEDE on an existing file to report Superseded.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.EndOfFile, "Expected FILE_SUPERSEDE to replace the existing file with an empty file.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.AllocationSize, "Expected FILE_SUPERSEDE to reset declared allocation state after replacement.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> supersedeClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = supersedeResult.Response.PersistentFileId,
                                        VolatileFileId = supersedeResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, supersedeClose.Status, "Expected the superseded file open to close cleanly.");
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "supersede.txt")).Length, "Expected FILE_SUPERSEDE to leave the backing file truncated.");
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


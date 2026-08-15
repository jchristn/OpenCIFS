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
    internal static class ServerFileIoDeletionAndDispositionCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerEnforcesShareModesAndDeletePendingLifecycle",
                        displayName: "Server enforces SMB2 share modes and delete-on-close pending behavior",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> sharedReadOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000001U));
                                TestAssertions.Equal(NtStatus.Success, sharedReadOpen.Status, "Expected the first read-only open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> writeConflict = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x40000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.SharingViolation, writeConflict.Status, "Expected a write open to fail when the existing open does not share write access.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> shareConflict = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000000U));
                                TestAssertions.Equal(NtStatus.SharingViolation, shareConflict.Status, "Expected an open to fail when it does not share read access back to the existing reader.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> sharedClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = sharedReadOpen.Response.PersistentFileId,
                                        VolatileFileId = sharedReadOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, sharedClose.Status, "Expected the read-only share-mode open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> deleteOnCloseOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "delete-me.txt",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseOpen.Status, "Expected delete-on-close create to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> deletePendingOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("delete-me.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.DeletePending, deletePendingOpen.Status, "Expected a new open against a delete-pending file to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> deleteOnCloseClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = deleteOnCloseOpen.Response.PersistentFileId,
                                        VolatileFileId = deleteOnCloseOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseClose.Status, "Expected delete-on-close open to close cleanly.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "delete-me.txt")), "Expected the delete-on-close file to be removed when the last open closes.");
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
                        caseId: "ServerAppliesCreateTimeFileAttributesAndRejectsReadOnlyDeleteOnCloseCreates",
                        displayName: "Server applies bounded create-time file attributes and rejects read-only delete-on-close creates",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite-hidden.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "created-hidden.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0xC0000000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                TestAssertions.Equal(NtStatus.Success, hiddenCreateResult.Status, "Expected hidden file create to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, hiddenCreateResult.Response.CreateAction, "Expected hidden file create to report Created.");
                                TestAssertions.True(
                                    (hiddenCreateResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected hidden file create to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "created-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the backing file to receive the Hidden attribute on create.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenCreateClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = hiddenCreateResult.Response.PersistentFileId,
                                        VolatileFileId = hiddenCreateResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, hiddenCreateClose.Status, "Expected the hidden create open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenOverwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "overwrite-hidden.txt",
                                        Smb2CreateDisposition.OverwriteIf,
                                        desiredAccess: 0xC0000000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                TestAssertions.Equal(NtStatus.Success, hiddenOverwriteResult.Status, "Expected hidden overwrite-if to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, hiddenOverwriteResult.Response.CreateAction, "Expected hidden overwrite-if on an existing file to report Overwritten.");
                                TestAssertions.True(
                                    (hiddenOverwriteResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected hidden overwrite-if to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "overwrite-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected overwrite-if to apply the Hidden attribute to the backing file.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenOverwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = hiddenOverwriteResult.Response.PersistentFileId,
                                        VolatileFileId = hiddenOverwriteResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, hiddenOverwriteClose.Status, "Expected the hidden overwrite-if open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDeleteOnCloseCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "transient-readonly.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0xC0010000U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDeleteOnCloseCreate.Status, "Expected read-only FILE_DELETE_ON_CLOSE on a new file to fail with STATUS_CANNOT_DELETE.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient-readonly.txt")), "Expected failed read-only delete-on-close create requests not to materialize a backing file.");
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
                        caseId: "ServerRejectsReadOnlyDeleteOnCloseForExistingAndDirectoryTargets",
                        displayName: "Server rejects read-only delete-on-close requests for existing files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-file.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileOpen.Status, "Expected existing read-only files to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the existing read-only file to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryOpen.Status, "Expected existing read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the existing read-only directory to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-created-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory | OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryCreate.Status, "Expected new read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "readonly-created-directory")), "Expected failed read-only directory creates not to materialize a backing directory.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerDeletesEmptyDirectoriesAndRejectsNonEmptyDirectoryDeletePending",
                        displayName: "Server deletes empty directories on last close and rejects non-empty directory delete-pending requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-empty"));
                            string existingNonEmptyPath = Path.Combine(sharePath, "existing-nonempty");
                            Directory.CreateDirectory(existingNonEmptyPath);
                            File.WriteAllText(Path.Combine(existingNonEmptyPath, "child.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> deleteOnCloseDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-empty",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseDirectoryOpen.Status, "Expected FILE_DELETE_ON_CLOSE on an existing empty directory to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> pendingChildCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("existing-empty\\child.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, pendingChildCreate.Status, "Expected child creates beneath a delete-pending directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> deleteOnCloseDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = deleteOnCloseDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = deleteOnCloseDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseDirectoryClose.Status, "Expected the delete-on-close directory open to close cleanly.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "existing-empty")), "Expected the empty delete-on-close directory to be removed on last close.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dispositionDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "disposition-empty",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, dispositionDirectoryOpen.Status, "Expected creating a directory for FILE_DISPOSITION_INFORMATION coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionSetResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = dispositionDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = dispositionDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionSetResult.Status, "Expected FILE_DISPOSITION_INFORMATION to allow delete-pending on an empty directory.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dispositionChildCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("disposition-empty\\child.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, dispositionChildCreate.Status, "Expected child creates beneath a disposition-marked directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> dispositionDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = dispositionDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = dispositionDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionDirectoryClose.Status, "Expected the disposition-marked directory open to close cleanly.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "disposition-empty")), "Expected the disposition-marked empty directory to be removed on last close.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> nonEmptyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-nonempty",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, nonEmptyDirectoryOpen.Status, "Expected opening the non-empty directory to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> nonEmptyDispositionResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = nonEmptyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = nonEmptyDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, nonEmptyDispositionResult.Status, "Expected non-empty directories to reject delete-pending requests.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> nonEmptyDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = nonEmptyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = nonEmptyDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, nonEmptyDirectoryClose.Status, "Expected the non-empty directory open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(Directory.Exists(existingNonEmptyPath), "Expected the non-empty directory to remain after the failed delete-pending request.");
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
            };
        }
    }
}


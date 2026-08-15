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
    internal static class LoopbackFileIoCreationAndOverwriteCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerCreateDirectoriesThroughBoundedCreateDispositions",
                        displayName: "Client and server loopback create directories through bounded SMB2 FILE_DIRECTORY_FILE create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-directory"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createDirectoryRequest = client.CreateCreateRequest(
                                    treeId,
                                    "loopback-directory",
                                    desiredAccess: 0x80000000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Create,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createDirectoryResult = server.HandleCreate(client.SessionId!.Value, treeId, createDirectoryRequest);
                                OpenState createdDirectoryOpen = client.ApplyCreateResult(treeId, "loopback-directory", createDirectoryResult.Status, createDirectoryResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, createDirectoryResult.Response.CreateAction, "Expected loopback FILE_CREATE on a directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "loopback-directory")), "Expected the loopback create request to materialize the backing directory.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> createDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(createdDirectoryOpen.PersistentFileId, createdDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(createdDirectoryOpen.PersistentFileId, createdDirectoryOpen.VolatileFileId, createDirectoryClose.Status, createDirectoryClose.Response);

                                Smb2CreateRequest existingDirectoryOpenIfRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x80000000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> existingDirectoryOpenIfResult = server.HandleCreate(client.SessionId!.Value, treeId, existingDirectoryOpenIfRequest);
                                OpenState existingDirectoryOpen = client.ApplyCreateResult(treeId, "existing-directory", existingDirectoryOpenIfResult.Status, existingDirectoryOpenIfResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Opened, existingDirectoryOpenIfResult.Response.CreateAction, "Expected loopback FILE_OPEN_IF on an existing directory to report Opened.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> existingDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(existingDirectoryOpen.PersistentFileId, existingDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(existingDirectoryOpen.PersistentFileId, existingDirectoryOpen.VolatileFileId, existingDirectoryClose.Status, existingDirectoryClose.Response);

                                Smb2CreateRequest plainExistingDirectoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x00000080U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.None);
                                OpenCifsServerOperationResult<Smb2CreateResponse> plainExistingDirectoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, plainExistingDirectoryOpenRequest);
                                OpenState plainExistingDirectoryOpen = client.ApplyCreateResult(treeId, "existing-directory", plainExistingDirectoryOpenResult.Status, plainExistingDirectoryOpenResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Opened, plainExistingDirectoryOpenResult.Response.CreateAction, "Expected loopback plain opens of existing directories to report Opened.");
                                TestAssertions.True((plainExistingDirectoryOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected loopback plain opens of existing directories to return directory metadata.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> plainExistingDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(plainExistingDirectoryOpen.PersistentFileId, plainExistingDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(plainExistingDirectoryOpen.PersistentFileId, plainExistingDirectoryOpen.VolatileFileId, plainExistingDirectoryClose.Status, plainExistingDirectoryClose.Response);

                                Smb2CreateRequest nonDirectoryExistingDirectoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x00000080U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Normal,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.NonDirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> nonDirectoryExistingDirectoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, nonDirectoryExistingDirectoryOpenRequest);
                                TestAssertions.Equal(NtStatus.FileIsADirectory, nonDirectoryExistingDirectoryOpenResult.Status, "Expected loopback explicit FILE_NON_DIRECTORY_FILE opens against an existing directory to remain rejected.");

                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear directory opens after the bounded loopback directory-create slice closes them.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerOverwriteAndSupersedeFiles",
                        displayName: "Client and server loopback overwrite and supersede files through bounded SMB2 create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> seedOverwriteCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "overwrite-target.txt"));
                                OpenState seedOverwriteOpen = client.ApplyCreateResult(treeId, "overwrite-target.txt", seedOverwriteCreate.Status, seedOverwriteCreate.Response);
                                byte[] overwritePayload = Encoding.UTF8.GetBytes("seed overwrite");
                                OpenCifsServerOperationResult<Smb2WriteResponse> seedOverwriteWrite = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, overwritePayload, 0));
                                client.ApplyWriteResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteWrite.Status, seedOverwriteWrite.Response);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seedOverwriteAllocation = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, 64));
                                client.ApplySetInfoResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteAllocation.Status, seedOverwriteAllocation.Response);
                                OpenCifsServerOperationResult<Smb2CloseResponse> seedOverwriteClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId));
                                client.ApplyCloseResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteClose.Status, seedOverwriteClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-target.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf));
                                OpenState overwrittenOpen = client.ApplyCreateResult(treeId, "overwrite-target.txt", overwriteIfResult.Status, overwriteIfResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, overwriteIfResult.Response.CreateAction, "Expected loopback FILE_OVERWRITE_IF on an existing file to report Overwritten.");
                                TestAssertions.Equal(0UL, overwriteIfResult.Response.EndOfFile, "Expected loopback FILE_OVERWRITE_IF to truncate the existing file.");
                                TestAssertions.Equal(0UL, overwriteIfResult.Response.AllocationSize, "Expected loopback FILE_OVERWRITE_IF to reset declared allocation state after truncation.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwrittenClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId));
                                client.ApplyCloseResult(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId, overwrittenClose.Status, overwrittenClose.Response);
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "overwrite-target.txt")).Length, "Expected loopback FILE_OVERWRITE_IF to leave the backing file truncated.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfCreatedResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-created.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf));
                                OpenState overwriteIfCreatedOpen = client.ApplyCreateResult(treeId, "overwrite-created.txt", overwriteIfCreatedResult.Status, overwriteIfCreatedResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, overwriteIfCreatedResult.Response.CreateAction, "Expected loopback FILE_OVERWRITE_IF on a missing file to report Created.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteIfCreatedClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(overwriteIfCreatedOpen.PersistentFileId, overwriteIfCreatedOpen.VolatileFileId));
                                client.ApplyCloseResult(overwriteIfCreatedOpen.PersistentFileId, overwriteIfCreatedOpen.VolatileFileId, overwriteIfCreatedClose.Status, overwriteIfCreatedClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> seedSupersedeCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "supersede-target.txt"));
                                OpenState seedSupersedeOpen = client.ApplyCreateResult(treeId, "supersede-target.txt", seedSupersedeCreate.Status, seedSupersedeCreate.Response);
                                byte[] supersedePayload = Encoding.UTF8.GetBytes("seed supersede");
                                OpenCifsServerOperationResult<Smb2WriteResponse> seedSupersedeWrite = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, supersedePayload, 0));
                                client.ApplyWriteResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeWrite.Status, seedSupersedeWrite.Response);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seedSupersedeAllocation = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, 96));
                                client.ApplySetInfoResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeAllocation.Status, seedSupersedeAllocation.Response);
                                OpenCifsServerOperationResult<Smb2CloseResponse> seedSupersedeClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId));
                                client.ApplyCloseResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeClose.Status, seedSupersedeClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> supersedeResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "supersede-target.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Supersede));
                                OpenState supersededOpen = client.ApplyCreateResult(treeId, "supersede-target.txt", supersedeResult.Status, supersedeResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Superseded, supersedeResult.Response.CreateAction, "Expected loopback FILE_SUPERSEDE on an existing file to report Superseded.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.EndOfFile, "Expected loopback FILE_SUPERSEDE to replace the file with an empty one.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.AllocationSize, "Expected loopback FILE_SUPERSEDE to reset declared allocation state after replacement.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> supersedeClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId));
                                client.ApplyCloseResult(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId, supersedeClose.Status, supersedeClose.Response);
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "supersede-target.txt")).Length, "Expected loopback FILE_SUPERSEDE to leave the backing file truncated.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback overwrite and supersede slice to close all tracked opens.");
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


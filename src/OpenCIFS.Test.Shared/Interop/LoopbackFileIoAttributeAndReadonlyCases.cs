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
    internal static class LoopbackFileIoAttributeAndReadonlyCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerApplyCreateTimeFileAttributesAndRejectReadOnlyDeleteOnCloseCreates",
                        displayName: "Client and server loopback apply bounded create-time file attributes and reject read-only delete-on-close creates",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite-hidden.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "created-hidden.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                OpenState hiddenCreateOpen = client.ApplyCreateResult(treeId, "created-hidden.txt", hiddenCreateResult.Status, hiddenCreateResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, hiddenCreateResult.Response.CreateAction, "Expected loopback hidden create to report Created.");
                                TestAssertions.True(
                                    (hiddenCreateResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected loopback hidden create to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "created-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the loopback hidden create to apply the Hidden attribute to the backing file.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenCreateClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(hiddenCreateOpen.PersistentFileId, hiddenCreateOpen.VolatileFileId));
                                client.ApplyCloseResult(hiddenCreateOpen.PersistentFileId, hiddenCreateOpen.VolatileFileId, hiddenCreateClose.Status, hiddenCreateClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenOverwriteResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-hidden.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                OpenState hiddenOverwriteOpen = client.ApplyCreateResult(treeId, "overwrite-hidden.txt", hiddenOverwriteResult.Status, hiddenOverwriteResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, hiddenOverwriteResult.Response.CreateAction, "Expected loopback hidden overwrite-if on an existing file to report Overwritten.");
                                TestAssertions.True(
                                    (hiddenOverwriteResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected loopback hidden overwrite-if to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "overwrite-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the loopback hidden overwrite-if to apply the Hidden attribute to the backing file.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenOverwriteClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(hiddenOverwriteOpen.PersistentFileId, hiddenOverwriteOpen.VolatileFileId));
                                client.ApplyCloseResult(hiddenOverwriteOpen.PersistentFileId, hiddenOverwriteOpen.VolatileFileId, hiddenOverwriteClose.Status, hiddenOverwriteClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDeleteOnCloseCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "transient-readonly.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDeleteOnCloseCreate.Status, "Expected loopback read-only FILE_DELETE_ON_CLOSE on a new file to fail with STATUS_CANNOT_DELETE.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient-readonly.txt")), "Expected loopback read-only delete-on-close create failures not to materialize a backing file.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback create-attribute slice to close all tracked opens.");
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
                        caseId: "ClientAndServerRejectReadOnlyDeleteOnCloseForExistingAndDirectoryTargets",
                        displayName: "Client and server loopback reject read-only delete-on-close requests for existing files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-file.txt",
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileOpen.Status, "Expected loopback existing read-only files to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the loopback existing read-only file to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryOpen.Status, "Expected loopback existing read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the loopback existing read-only directory to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-created-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory | OpenCIFS.Protocol.FileAttributes.ReadOnly,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryCreate.Status, "Expected loopback new read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "readonly-created-directory")), "Expected failed loopback read-only directory creates not to materialize a backing directory.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback read-only delete-on-close failure slice not to create tracked opens.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
            };
        }
    }
}


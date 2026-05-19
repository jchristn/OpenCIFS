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
    internal static class LoopbackFileIoPendingAndValidationCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerDeleteDeleteOnCloseFileAndBlockReopen",
                        displayName: "Client and server loopback delete a delete-on-close file and reject reopen while it is pending",
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

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "transient.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "transient.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("temporary");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected delete-on-close loopback write count.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> reopenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "transient.txt", createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.DeletePending, reopenResult.Status, "Expected loopback reopen to fail while the file is delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient.txt")), "Expected the delete-on-close loopback file to be removed when the last open closes.");
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
                        caseId: "ClientAndServerRejectInvalidIdentifiersAcrossFileIoSurface",
                        displayName: "Client and server loopback reject invalid session, tree, and open identifiers across the bounded file-I/O surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropInvalidIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "identifiers.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "identifiers.txt", createResult.Status, createResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateSessionResult = server.HandleCreate(
                                    client.SessionId.Value + 1,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "other.txt"));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateSessionResult.Status, "Expected loopback create requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCreateResult(treeId, "other.txt", invalidCreateSessionResult.Status, invalidCreateSessionResult.Response),
                                    "Expected the client to surface invalid-session create failures.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateTreeResult = server.HandleCreate(
                                    client.SessionId.Value,
                                    treeId + 1,
                                    client.CreateCreateRequest(treeId, "other.txt"));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateTreeResult.Status, "Expected loopback create requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCreateResult(treeId, "other.txt", invalidCreateTreeResult.Status, invalidCreateTreeResult.Response),
                                    "Expected the client to surface invalid-tree create failures.");

                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0);
                                OpenCifsServerOperationResult<Smb2ReadResponse> invalidReadSessionResult = server.HandleRead(client.SessionId.Value + 1, treeId, readRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidReadSessionResult.Status, "Expected loopback read requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, invalidReadSessionResult.Status, invalidReadSessionResult.Response),
                                    "Expected the client to surface invalid-session read failures.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> invalidReadTreeResult = server.HandleRead(client.SessionId.Value, treeId + 1, readRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidReadTreeResult.Status, "Expected loopback read requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, invalidReadTreeResult.Status, invalidReadTreeResult.Response),
                                    "Expected the client to surface invalid-tree read failures.");

                                byte[] payload = Encoding.UTF8.GetBytes("x");
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                OpenCifsServerOperationResult<Smb2WriteResponse> invalidWriteSessionResult = server.HandleWrite(client.SessionId.Value + 1, treeId, writeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidWriteSessionResult.Status, "Expected loopback write requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, invalidWriteSessionResult.Status, invalidWriteSessionResult.Response),
                                    "Expected the client to surface invalid-session write failures.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> invalidWriteTreeResult = server.HandleWrite(client.SessionId.Value, treeId + 1, writeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidWriteTreeResult.Status, "Expected loopback write requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, invalidWriteTreeResult.Status, invalidWriteTreeResult.Response),
                                    "Expected the client to surface invalid-tree write failures.");

                                Smb2FlushRequest flushRequest = client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                                OpenCifsServerOperationResult<Smb2FlushResponse> invalidFlushSessionResult = server.HandleFlush(client.SessionId.Value + 1, treeId, flushRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidFlushSessionResult.Status, "Expected loopback flush requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, invalidFlushSessionResult.Status, invalidFlushSessionResult.Response),
                                    "Expected the client to surface invalid-session flush failures.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> invalidFlushTreeResult = server.HandleFlush(client.SessionId.Value, treeId + 1, flushRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidFlushTreeResult.Status, "Expected loopback flush requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, invalidFlushTreeResult.Status, invalidFlushTreeResult.Response),
                                    "Expected the client to surface invalid-tree flush failures.");

                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> invalidCloseSessionResult = server.HandleClose(client.SessionId.Value + 1, treeId, closeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCloseSessionResult.Status, "Expected loopback close requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, invalidCloseSessionResult.Status, invalidCloseSessionResult.Response),
                                    "Expected the client to surface invalid-session close failures.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> invalidCloseTreeResult = server.HandleClose(client.SessionId.Value, treeId + 1, closeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCloseTreeResult.Status, "Expected loopback close requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, invalidCloseTreeResult.Status, invalidCloseTreeResult.Response),
                                    "Expected the client to surface invalid-tree close failures.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(client.SessionId.Value, treeId, closeRequest);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerDeleteEmptyDirectoryAndBlockChildCreatesWhilePending",
                        displayName: "Client and server loopback delete an empty directory on last close and block child creates while it is pending",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "transient-directory"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "transient-directory",
                                    desiredAccess: 0x80010000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, directoryOpenRequest);
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "transient-directory", directoryOpenResult.Status, directoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> childCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "transient-directory/child.txt", createDisposition: Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, childCreateResult.Status, "Expected loopback child creates beneath a delete-pending directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "transient-directory")), "Expected the loopback empty directory to be removed when the last delete-pending open closes.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the delete-pending directory open after close.");
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


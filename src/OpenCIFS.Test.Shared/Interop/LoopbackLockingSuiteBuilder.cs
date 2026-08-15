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
    internal static class LoopbackLockingSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackLocking",
                displayName: "Loopback byte-range locking coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackLocking",
                        caseId: "ClientAndServerApplyByteRangeLocksAndRejectConflicts",
                        displayName: "Client and server loopback apply byte-range locks and reject conflicting lock and read requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "0123456789");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> firstCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "locked.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState firstOpen = client.ApplyCreateResult(treeId, "locked.txt", firstCreateResult.Status, firstCreateResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> secondCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "locked.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState secondOpen = client.ApplyCreateResult(treeId, "locked.txt", secondCreateResult.Status, secondCreateResult.Response);
                                TestAssertions.Equal(2, client.OpenCount, "Expected the client to track both loopback locking opens.");

                                Smb2LockRequest firstLockRequest = client.CreateLockRequest(
                                    firstOpen.PersistentFileId,
                                    firstOpen.VolatileFileId,
                                    new Smb2LockElement
                                    {
                                        Offset = 2,
                                        Length = 4,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    });
                                OpenCifsServerOperationResult<Smb2LockResponse> firstLockResult = server.HandleLock(client.SessionId.Value, treeId, firstLockRequest);
                                client.ApplyLockResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstLockResult.Status, firstLockResult.Response);

                                Smb2LockRequest conflictingLockRequest = client.CreateLockRequest(
                                    secondOpen.PersistentFileId,
                                    secondOpen.VolatileFileId,
                                    new Smb2LockElement
                                    {
                                        Offset = 2,
                                        Length = 4,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    });
                                OpenCifsServerOperationResult<Smb2LockResponse> conflictingLockResult = server.HandleLock(client.SessionId.Value, treeId, conflictingLockRequest);
                                TestAssertions.Equal(NtStatus.LockNotGranted, conflictingLockResult.Status, "Expected a conflicting loopback lock request to fail.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> conflictingReadResult = server.HandleRead(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateReadRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId, 2, 2));
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingReadResult.Status, "Expected a competing loopback read to fail inside the exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = server.HandleLock(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateLockRequest(
                                        firstOpen.PersistentFileId,
                                        firstOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 2,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }));
                                client.ApplyLockResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, unlockResult.Status, unlockResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("AB");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateWriteRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId, payload, 2));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(secondOpen.PersistentFileId, secondOpen.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback post-unlock write count.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> firstCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId));
                                client.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstCloseResult.Status, firstCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId));
                                client.ApplyCloseResult(secondOpen.PersistentFileId, secondOpen.VolatileFileId, secondCloseResult.Status, secondCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear both loopback locking opens after close.");
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

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
    internal static class LoopbackLeaseSuiteBuilder
    {
        internal static TestSuiteDescriptor LoopbackLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackLease",
                displayName: "Loopback SMB 2.1 lease coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackLease",
                        caseId: "ClientAndServerCompleteSignedLeaseBreakFlow",
                        displayName: "Client and server loopback complete a signed lease-break flow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession watcherClient = CreateClient();
                                OpenCifsClientSession actorClient = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint watcherTreeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, watcherClient, credential, creditRequest: 5);
                                uint actorTreeId = AuthenticateLoopbackSessionAndTree(server, actorClient, credential);
                                ulong watcherSessionId = watcherClient.SessionId!.Value;
                                ulong actorSessionId = actorClient.SessionId!.Value;
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 1);
                                }

                                Smb2Header firstOpenHeader = watcherClient.CreateRequestHeader(Smb2Command.Create, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CreateRequest firstOpenRequest = watcherClient.CreateCreateRequest(
                                    watcherTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    leaseKey: leaseKey);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(watcherSessionId, watcherTreeId, firstOpenRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                OpenState watcherOpen = watcherClient.ApplyCreateResult(watcherTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Lease, watcherOpen.OplockLevel, "Expected the first loopback open to receive an SMB 2.1 lease.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, watcherOpen.LeaseState, "Expected the first loopback open to receive a full read-write-handle lease.");

                                Smb2CreateRequest secondOpenRequest = actorClient.CreateCreateRequest(
                                    actorTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(actorSessionId, actorTreeId, secondOpenRequest);
                                OpenState actorOpen = actorClient.ApplyCreateResult(actorTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second loopback open not to receive a lease grant.");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue a lease-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = server.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                watcherClient.ValidateLeaseBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);
                                Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                OpenCifsClientLeaseBreakNotificationResult leaseBreakResult =
                                    watcherClient.ApplyLeaseBreakNotification(watcherTreeId, notification);
                                OpenState appliedOpenState = leaseBreakResult.OpenState;
                                Smb2LeaseState previousLeaseState = leaseBreakResult.PreviousLeaseState;
                                Smb2LeaseState newLeaseState = leaseBreakResult.NewLeaseState;
                                bool requiresAcknowledgment = leaseBreakResult.RequiresAcknowledgment;
                                TestAssertions.Equal(watcherOpen.PersistentFileId, appliedOpenState.PersistentFileId, "Expected the loopback lease-break notification to target the original open.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, previousLeaseState, "Expected the loopback lease-break flow to preserve the previous read-write-handle lease.");
                                TestAssertions.Equal(Smb2LeaseState.None, newLeaseState, "Expected the loopback lease-break flow to lower the lease state to none.");
                                TestAssertions.True(requiresAcknowledgment, "Expected loopback lease breaks to require acknowledgment.");

                                Smb2LeaseBreakAcknowledgment acknowledgment = watcherClient.CreateLeaseBreakAcknowledgmentRequest(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId);
                                Smb2Header acknowledgmentHeader = watcherClient.CreateRequestHeader(Smb2Command.OplockBreak, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CompoundPacket acknowledgmentPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(acknowledgmentHeader, acknowledgment.ToByteArray())
                                });
                                byte[] acknowledgmentPacketBytes = watcherClient.FinalizeRequestPacket(acknowledgmentPacket);
                                Smb2CompoundPacket parsedAcknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                server.ValidateRequestPacket(parsedAcknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = server.HandleCompoundRequestPacket(parsedAcknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = server.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                watcherClient.ValidateResponsePacket(parsedAcknowledgmentResponsePacket, acknowledgmentResponseBytes);
                                watcherClient.ApplyResponseHeader(parsedAcknowledgmentResponsePacket.Entries[0].Header);
                                watcherClient.ApplyLeaseBreakAcknowledgmentResult(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    parsedAcknowledgmentResponsePacket.Entries[0].Header.Status,
                                    Smb2LeaseBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload));
                                TestAssertions.Equal(Smb2LeaseState.None, watcherOpen.LeaseState, "Expected the loopback lease-break acknowledgment to preserve the lowered lease state.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> actorCloseResult = server.HandleClose(
                                    actorSessionId,
                                    actorTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = actorOpen.PersistentFileId,
                                        VolatileFileId = actorOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, actorCloseResult.Status, "Expected the actor loopback open to close cleanly after the lease-break flow.");

                                Smb2Header watcherCloseHeader = watcherClient.CreateRequestHeader(Smb2Command.Close, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CloseRequest watcherCloseRequest = watcherClient.CreateCloseRequest(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watcherCloseHeader, Smb2Command.Close, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watcherCloseResult = server.HandleClose(watcherSessionId, watcherTreeId, watcherCloseRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(watcherCloseHeader, watcherCloseResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                watcherClient.ApplyCloseResult(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId, watcherCloseResult.Status, watcherCloseResult.Response);
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
                        suiteId: "Interop.LoopbackLease",
                        caseId: "ClientAndServerRejectSameLeaseKeyOnDifferentPath",
                        displayName: "Client and server loopback reject the same lease key on a different path",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "first.txt"), "first");
                            File.WriteAllText(Path.Combine(sharePath, "other.txt"), "other");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 21);
                                }

                                Smb2Header firstOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest firstOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "first.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                    leaseKey: leaseKey);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(sessionId, treeId, firstOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState firstOpen = client.ApplyCreateResult(treeId, "first.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.OplockLevel, "Expected the initial loopback lease-backed open to succeed.");

                                Smb2CreateRequest secondOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "other.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(sessionId, treeId, secondOpenRequest);
                                TestAssertions.Equal(NtStatus.InvalidParameter, secondOpenResult.Status, "Expected the same lease key on a different path to be rejected.");

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(sessionId, treeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, closeResult.Status, closeResult.Response);
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

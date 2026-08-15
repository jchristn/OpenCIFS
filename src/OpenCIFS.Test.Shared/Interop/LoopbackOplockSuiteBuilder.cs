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
    internal static class LoopbackOplockSuiteBuilder
    {
        internal static TestSuiteDescriptor LoopbackOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackOplock",
                displayName: "Loopback oplock-break coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackOplock",
                        caseId: "ClientAndServerCompleteSignedExclusiveOplockBreakFlow",
                        displayName: "Client and server loopback complete a signed exclusive oplock-break flow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropOplock_" + Guid.NewGuid().ToString("N"));
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

                                Smb2Header firstOpenHeader = watcherClient.CreateRequestHeader(Smb2Command.Create, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CreateRequest firstOpenRequest = watcherClient.CreateCreateRequest(
                                    watcherTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(watcherSessionId, watcherTreeId, firstOpenRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                OpenState watcherOpen = watcherClient.ApplyCreateResult(watcherTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, watcherOpen.OplockLevel, "Expected the first loopback open to receive an exclusive oplock.");

                                Smb2CreateRequest secondOpenRequest = actorClient.CreateCreateRequest(
                                    actorTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(actorSessionId, actorTreeId, secondOpenRequest);
                                OpenState actorOpen = actorClient.ApplyCreateResult(actorTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second loopback open not to receive an oplock grant.");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue an oplock-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = server.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                watcherClient.ValidateOplockBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);
                                Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                OpenCifsClientOplockBreakNotificationResult oplockBreakResult =
                                    watcherClient.ApplyOplockBreakNotification(watcherTreeId, notification);
                                OpenState appliedOpenState = oplockBreakResult.OpenState;
                                Smb2OplockLevel previousOplockLevel = oplockBreakResult.PreviousOplockLevel;
                                Smb2OplockLevel newOplockLevel = oplockBreakResult.NewOplockLevel;
                                bool requiresAcknowledgment = oplockBreakResult.RequiresAcknowledgment;
                                TestAssertions.Equal(watcherOpen.PersistentFileId, appliedOpenState.PersistentFileId, "Expected the loopback oplock-break notification to target the original open.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, previousOplockLevel, "Expected the loopback oplock-break flow to preserve the previous exclusive oplock.");
                                TestAssertions.Equal(Smb2OplockLevel.None, newOplockLevel, "Expected the loopback oplock-break flow to lower the oplock to none.");
                                TestAssertions.True(requiresAcknowledgment, "Expected exclusive loopback oplock breaks to require acknowledgment.");

                                Smb2OplockBreakAcknowledgment acknowledgment = watcherClient.CreateOplockBreakAcknowledgmentRequest(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    Smb2OplockLevel.None);
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
                                watcherClient.ApplyOplockBreakAcknowledgmentResult(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    parsedAcknowledgmentResponsePacket.Entries[0].Header.Status,
                                    Smb2OplockBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload));
                                TestAssertions.Equal(Smb2OplockLevel.None, watcherOpen.OplockLevel, "Expected the loopback oplock-break acknowledgment to preserve the lowered oplock state.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> actorCloseResult = server.HandleClose(
                                    actorSessionId,
                                    actorTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = actorOpen.PersistentFileId,
                                        VolatileFileId = actorOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, actorCloseResult.Status, "Expected the actor loopback open to close cleanly after the oplock-break flow.");

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
                        suiteId: "Interop.LoopbackOplock",
                        caseId: "ClientAndServerRejectExclusiveOplockWhenFileAlreadyHasOpen",
                        displayName: "Client and server loopback reject an exclusive oplock when the file already has an open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession firstClient = CreateClient();
                                OpenCifsClientSession secondClient = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, firstClient, credential, creditRequest: 4);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(server, secondClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2Header firstOpenHeader = firstClient.CreateRequestHeader(Smb2Command.Create, firstTreeId, sessionId: firstSessionId);
                                Smb2CreateRequest firstOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: firstSessionId, expectedTreeId: firstTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                firstClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: firstSessionId, treeId: firstTreeId));
                                OpenState firstOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, firstOpen.OplockLevel, "Expected the first loopback open without an oplock request not to receive an oplock grant.");

                                Smb2CreateRequest secondOpenRequest = secondClient.CreateCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(secondSessionId, secondTreeId, secondOpenRequest);
                                OpenState secondOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.OplockLevel, "Expected the second loopback open not to receive an exclusive oplock while the file already has an open.");
                                TestAssertions.False(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? _), "Expected loopback oplock coverage not to queue an unsolicited break when no oplock was granted.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondCloseResult = server.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = secondOpen.PersistentFileId,
                                        VolatileFileId = secondOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondCloseResult.Status, "Expected the second loopback open to close cleanly after the rejected oplock grant.");

                                Smb2Header firstCloseHeader = firstClient.CreateRequestHeader(Smb2Command.Close, firstTreeId, sessionId: firstSessionId);
                                Smb2CloseRequest firstCloseRequest = firstClient.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(firstCloseHeader, Smb2Command.Close, expectedSessionId: firstSessionId, expectedTreeId: firstTreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> firstCloseResult = server.HandleClose(firstSessionId, firstTreeId, firstCloseRequest);
                                firstClient.ApplyResponseHeader(server.CreateResponseHeader(firstCloseHeader, firstCloseResult.Status, sessionId: firstSessionId, treeId: firstTreeId));
                                firstClient.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstCloseResult.Status, firstCloseResult.Response);
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

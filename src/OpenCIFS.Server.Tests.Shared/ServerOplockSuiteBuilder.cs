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
    internal static class ServerOplockSuiteBuilder
    {
        internal static TestSuiteDescriptor ServerOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Oplock",
                displayName: "Server oplock-break handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Oplock",
                        caseId: "ServerGrantsExclusiveOplockAndCompletesSignedBreakAcknowledgment",
                        displayName: "Server grants exclusive oplocks and completes signed oplock-break acknowledgments",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedSigningContext firstSigningContext = AuthenticateSessionAndGetSigningKey(
                                    host,
                                    dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21 },
                                    expectedDialect: SmbDialect.Smb21);

                                ulong firstSessionId = firstSigningContext.SessionId;

                                byte[] signingKey = firstSigningContext.SigningKey;
                                OpenCifsServerTreeConnectResult firstTreeConnect = host.HandleTreeConnect(
                                    firstSessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstTreeConnect.Status, "Expected the first oplock tree connect to succeed.");

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Exclusive;
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeConnect.TreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first oplock test open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, firstOpen.Response.OplockLevel, "Expected the first oplock test open to receive an exclusive oplock.");

                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(host);

                                ulong secondSessionId = secondTreeContext.SessionId;

                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest(
                                        "shared.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the conflicting second open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.Response.OplockLevel, "Expected the conflicting second open not to receive an oplock grant.");

                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue an oplock-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = host.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                Smb2Header notificationHeader = parsedNotificationPacket.Entries[0].Header;
                                TestAssertions.Equal(Smb2Command.OplockBreak, notificationHeader.Command, "Expected the queued async response to surface as SMB2 OPLOCK_BREAK.");
                                TestAssertions.Equal(UInt64.MaxValue, notificationHeader.MessageId, "Expected unsolicited oplock-break notifications to use the wildcard message identifier.");
                                TestAssertions.Equal(firstSessionId, notificationHeader.SessionId, "Expected the queued oplock-break notification to target the original open session.");
                                TestAssertions.Equal(firstTreeConnect.TreeId, notificationHeader.TreeId, "Expected the queued oplock-break notification to target the original open tree.");
                                TestAssertions.True((notificationHeader.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign unsolicited oplock-break notifications.");
                                Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                TestAssertions.Equal(Smb2OplockLevel.None, notification.OplockLevel, "Expected the bounded server oplock-break notification to lower the oplock to none.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, notification.PersistentFileId, "Expected the queued oplock-break notification to reference the original open.");

                                Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    PersistentFileId = firstOpen.Response.PersistentFileId,
                                    VolatileFileId = firstOpen.Response.VolatileFileId
                                };
                                Smb2OplockBreakAcknowledgmentValidator.Validate(acknowledgment);
                                Smb2Header acknowledgmentHeader = CreateRequestHeader(
                                    Smb2Command.OplockBreak,
                                    messageId: 0,
                                    sessionId: firstSessionId,
                                    treeId: firstTreeConnect.TreeId,
                                    flags: Smb2HeaderFlags.Signed);
                                byte[] acknowledgmentPacketBytes = CreateSignedPacketBytes(acknowledgmentHeader, acknowledgment.ToByteArray(), signingKey);
                                Smb2CompoundPacket acknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                host.ValidateRequestPacket(acknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = host.HandleCompoundRequestPacket(acknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = host.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                Smb2Header acknowledgmentResponseHeader = parsedAcknowledgmentResponsePacket.Entries[0].Header;
                                TestAssertions.Equal(NtStatus.Success, acknowledgmentResponseHeader.Status, "Expected the oplock-break acknowledgment response to succeed.");
                                Smb2OplockBreakResponse acknowledgmentResponse = Smb2OplockBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload);
                                TestAssertions.Equal(Smb2OplockLevel.None, acknowledgmentResponse.OplockLevel, "Expected the oplock-break acknowledgment response to preserve the lowered oplock level.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the conflicting second open to close cleanly after the oplock-break acknowledgment flow.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeConnect.TreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the first oplock test open to close cleanly after the oplock-break acknowledgment flow.");
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
                        suiteId: "Server.Oplock",
                        caseId: "ServerRejectsInvalidOplockBreakAcknowledgmentState",
                        displayName: "Server rejects invalid oplock-break acknowledgment state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21);
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(host);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Exclusive;
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first oplock state test open to succeed.");

                                OpenCifsServerOperationResult<Smb2OplockBreakResponse> noPendingBreakResult = host.HandleOplockBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2OplockBreakAcknowledgment
                                    {
                                        OplockLevel = Smb2OplockLevel.None,
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.InvalidDeviceState, noPendingBreakResult.Status, "Expected unsolicited oplock-break acknowledgments without a queued break to fail.");

                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(host);

                                ulong secondSessionId = secondTreeContext.SessionId;

                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest(
                                        "shared.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the conflicting second open to succeed before invalid acknowledgment coverage.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? _), "Expected the conflicting second open to queue an oplock-break notification.");

                                OpenCifsServerOperationResult<Smb2OplockBreakResponse> wrongLevelBreakResult = host.HandleOplockBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2OplockBreakAcknowledgment
                                    {
                                        OplockLevel = Smb2OplockLevel.LevelII,
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.InvalidOplockProtocol, wrongLevelBreakResult.Status, "Expected oplock-break acknowledgments with the wrong lowered level to fail.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the conflicting second open to close cleanly after invalid oplock-break coverage.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the first oplock state test open to close cleanly after invalid acknowledgment coverage.");
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

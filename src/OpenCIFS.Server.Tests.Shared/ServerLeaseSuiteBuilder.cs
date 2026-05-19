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
    internal static class ServerLeaseSuiteBuilder
    {
        internal static TestSuiteDescriptor ServerLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Lease",
                displayName: "Server SMB 2.1 lease handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Lease",
                        caseId: "ServerGrantsReadWriteHandleLeaseAndCompletesSignedBreakAcknowledgment",
                        displayName: "Server grants a read-write-handle lease and completes a signed lease-break acknowledgment",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerLease_" + Guid.NewGuid().ToString("N"));
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
                                TestAssertions.Equal(NtStatus.Success, firstTreeConnect.Status, "Expected the first lease tree connect to succeed.");

                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 1);
                                }

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Lease;
                                firstOpenRequest.CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                {
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                                    }.ToCreateContext()
                                });
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeConnect.TreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first lease-backed open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.Response.OplockLevel, "Expected the first lease-backed open to receive an SMB 2.1 lease.");
                                Smb2CreateResponseLeaseContext firstLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts)[0]);
                                TestAssertions.SequenceEqual(leaseKey, firstLeaseResponse.LeaseKey, "Expected the lease response context to preserve the client lease key.");
                                TestAssertions.Equal(
                                    Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    firstLeaseResponse.LeaseState,
                                    "Expected the initial lease-backed open to receive a full read-write-handle lease.");

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

                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue a lease-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = host.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                Smb2Header notificationHeader = parsedNotificationPacket.Entries[0].Header;
                                TestAssertions.Equal(Smb2Command.OplockBreak, notificationHeader.Command, "Expected the queued lease break to surface as SMB2 OPLOCK_BREAK.");
                                TestAssertions.Equal(UInt64.MaxValue, notificationHeader.MessageId, "Expected unsolicited lease-break notifications to use the wildcard message identifier.");
                                TestAssertions.True((notificationHeader.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign unsolicited lease-break notifications.");
                                Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                TestAssertions.SequenceEqual(leaseKey, notification.LeaseKey, "Expected the queued lease-break notification to reference the original lease key.");
                                TestAssertions.Equal(
                                    Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    notification.CurrentLeaseState,
                                    "Expected the queued lease-break notification to reflect the granted lease state before the break.");
                                TestAssertions.Equal(Smb2LeaseState.None, notification.NewLeaseState, "Expected the bounded server lease-break notification to lower the lease state to none.");
                                TestAssertions.True(
                                    (notification.Flags & Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired) != 0,
                                    "Expected the bounded lease-break notification to require acknowledgment.");

                                Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
                                {
                                    LeaseKey = leaseKey,
                                    LeaseState = Smb2LeaseState.None
                                };
                                Smb2LeaseBreakAcknowledgmentValidator.Validate(acknowledgment);
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
                                Smb2LeaseBreakResponse acknowledgmentResponse = Smb2LeaseBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload);
                                TestAssertions.Equal(NtStatus.Success, parsedAcknowledgmentResponsePacket.Entries[0].Header.Status, "Expected the lease-break acknowledgment response to succeed.");
                                TestAssertions.Equal(Smb2LeaseState.None, acknowledgmentResponse.LeaseState, "Expected the lease-break acknowledgment response to preserve the lowered lease state.");

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
                                    "Expected the conflicting second open to close cleanly after the lease-break acknowledgment flow.");
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
                                    "Expected the first lease-backed open to close cleanly after the lease-break acknowledgment flow.");
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
                        suiteId: "Server.Lease",
                        caseId: "ServerRejectsMismatchedLeasePathsAndInvalidLeaseBreakAcknowledgments",
                        displayName: "Server rejects mismatched lease paths and invalid lease-break acknowledgments",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "first.txt"), "first");
                            File.WriteAllText(Path.Combine(sharePath, "other.txt"), "other");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21);
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(host);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 17);
                                }

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest("first.txt", Smb2CreateDisposition.Open);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Lease;
                                firstOpenRequest.CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                {
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching
                                    }.ToCreateContext()
                                });
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial lease-backed open to succeed.");

                                TestAssertions.Equal(
                                    NtStatus.InvalidParameter,
                                    host.HandleCreate(
                                        firstSessionId,
                                        firstTreeId,
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.Lease,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x80000000U,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.Open,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = "other.txt",
                                            CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                            {
                                                new Smb2CreateRequestLeaseContext
                                                {
                                                    LeaseKey = leaseKey,
                                                    LeaseState = Smb2LeaseState.ReadCaching
                                                }.ToCreateContext()
                                            })
                                        }).Status,
                                    "Expected the same lease key to be rejected for a different file path.");

                                OpenCifsServerOperationResult<Smb2LeaseBreakResponse> invalidAckResult = host.HandleLeaseBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2LeaseBreakAcknowledgment
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.None
                                    });
                                TestAssertions.Equal(NtStatus.InvalidDeviceState, invalidAckResult.Status, "Expected lease-break acknowledgments without a pending break to fail.");

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
                                    "Expected the initial lease-backed open to close cleanly after negative lease coverage.");
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

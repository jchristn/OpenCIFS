namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientLeaseSuiteBuilder
    {
        /// <summary>
        /// Build the client lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Lease",
                displayName: "Client SMB 2.1 lease handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Lease",
                        caseId: "ClientAppliesUnsignedLeaseBreakNotificationsAndAcknowledgesThem",
                        displayName: "Client applies unsigned lease-break notifications and acknowledges them",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            byte[] leaseKey = new byte[16];

                            for (int index = 0; index < leaseKey.Length; index++)
                            {
                                leaseKey[index] = (byte)(index + 1);
                            }

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "docs\\shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Lease,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 800,
                                    VolatileFileId = 801,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                    {
                                        new Smb2CreateResponseLeaseContext
                                        {
                                            LeaseKey = leaseKey,
                                            LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                                        }.ToCreateContext()
                                    })
                                });
                            TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, openState.LeaseState, "Expected the tracked open to adopt the granted lease state.");

                            Smb2Header notificationHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Success,
                                Command = Smb2Command.OplockBreak,
                                CreditRequest = 0,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 0,
                                AsyncId = 0,
                                SessionId = 0,
                                Signature = new byte[16]
                            };
                            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
                            {
                                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                LeaseKey = leaseKey,
                                CurrentLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                NewLeaseState = Smb2LeaseState.None
                            };
                            Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(notificationHeader, notification.ToByteArray())
                            });
                            byte[] notificationPacketBytes = session.FinalizeRequestPacket(notificationPacket);
                            Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                            session.ValidateLeaseBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);

                            OpenCifsClientLeaseBreakNotificationResult leaseBreakResult = session.ApplyLeaseBreakNotification(0, notification);

                            OpenState appliedOpenState = leaseBreakResult.OpenState;

                            Smb2LeaseState previousLeaseState = leaseBreakResult.PreviousLeaseState;

                            Smb2LeaseState newLeaseState = leaseBreakResult.NewLeaseState;

                            bool requiresAcknowledgment = leaseBreakResult.RequiresAcknowledgment;
                            TestAssertions.Equal(openState.PersistentFileId, appliedOpenState.PersistentFileId, "Expected the lease-break application to preserve the tracked open.");
                            TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, previousLeaseState, "Expected the previous lease state to remain read-write-handle.");
                            TestAssertions.Equal(Smb2LeaseState.None, newLeaseState, "Expected the notification to lower the tracked lease state to none.");
                            TestAssertions.True(requiresAcknowledgment, "Expected the lease break to require client acknowledgment.");
                            TestAssertions.Equal(Smb2LeaseState.None, openState.LeaseState, "Expected the tracked client open to adopt the lowered lease state immediately.");

                            Smb2LeaseBreakAcknowledgment acknowledgment = session.CreateLeaseBreakAcknowledgmentRequest(openState.PersistentFileId, openState.VolatileFileId);
                            Smb2LeaseBreakAcknowledgmentValidator.Validate(acknowledgment);
                            session.ApplyLeaseBreakAcknowledgmentResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2LeaseBreakResponse
                                {
                                    LeaseKey = leaseKey,
                                    LeaseState = Smb2LeaseState.None
                                });
                            TestAssertions.Equal(Smb2LeaseState.None, openState.LeaseState, "Expected successful lease-break acknowledgments to preserve the lowered client lease state.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Lease",
                        caseId: "ClientRejectsUnexpectedOrInvalidLeaseBreakNotifications",
                        displayName: "Client rejects unexpected or invalid lease-break notifications",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            byte[] leaseKey = new byte[16];

                            for (int index = 0; index < leaseKey.Length; index++)
                            {
                                leaseKey[index] = (byte)(index + 17);
                            }

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "docs\\shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Lease,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 800,
                                    VolatileFileId = 801,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                    {
                                        new Smb2CreateResponseLeaseContext
                                        {
                                            LeaseKey = leaseKey,
                                            LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching
                                        }.ToCreateContext()
                                    })
                                });

                            Smb2Header wrongSessionHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Success,
                                Command = Smb2Command.OplockBreak,
                                CreditRequest = 0,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 0,
                                AsyncId = 0,
                                SessionId = session.SessionId!.Value + 1,
                                Signature = new byte[16]
                            };
                            Smb2LeaseBreakNotification unsignedNotification = new Smb2LeaseBreakNotification
                            {
                                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                LeaseKey = leaseKey,
                                CurrentLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                NewLeaseState = Smb2LeaseState.None
                            };
                            byte[] unsignedPacketBytes = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(wrongSessionHeader, unsignedNotification.ToByteArray())
                            }).ToByteArray();
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ValidateLeaseBreakNotificationPacket(Smb2CompoundPacket.ReadFrom(unsignedPacketBytes), unsignedPacketBytes),
                                "Expected lease-break notifications from an unrelated session to be rejected.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyLeaseBreakNotification(
                                    99,
                                    new Smb2LeaseBreakNotification
                                    {
                                        Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                        LeaseKey = leaseKey,
                                        CurrentLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                        NewLeaseState = Smb2LeaseState.None
                                    }),
                                "Expected lease-break notifications for the wrong tree to be rejected.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyLeaseBreakNotification(
                                    42,
                                    new Smb2LeaseBreakNotification
                                    {
                                        Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                        LeaseKey = leaseKey,
                                        CurrentLeaseState = Smb2LeaseState.ReadCaching,
                                        NewLeaseState = Smb2LeaseState.None
                                    }),
                                "Expected lease-break notifications with a mismatched current state to be rejected.");
                            TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching, openState.LeaseState, "Expected the tracked client lease state to remain unchanged after negative validation coverage.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Lease",
                        caseId: "ClientConnectionCompletesLeaseBreakOverDirectTcp",
                        displayName: "Client connection completes lease-break handling over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watcherOpen = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.Lease, watcherOpen.OplockLevel, "Expected the first direct-TCP open to receive an SMB 2.1 lease grant.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, watcherOpen.LeaseState, "Expected the first direct-TCP open to receive a full read-write-handle lease.");

                                using CancellationTokenSource breakTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                breakTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<OpenCifsClientLeaseBreakNotification> breakTask = watcherClient.WaitForLeaseBreakAsync(breakTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle actorOpen = await actorClient.OpenAsync(
                                    actorTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientLeaseBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
                                TestAssertions.Equal("public", breakNotification.ShareName, "Expected the lease-break notification to retain the share name.");
                                TestAssertions.Equal("shared.txt", breakNotification.Path, "Expected the lease-break notification to retain the normalized path.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, breakNotification.PreviousLeaseState, "Expected the lease-break notification to report the previous read-write-handle lease.");
                                TestAssertions.Equal(Smb2LeaseState.None, breakNotification.NewLeaseState, "Expected the lease-break notification to lower the lease state to none.");
                                TestAssertions.True(breakNotification.WasAcknowledged, "Expected lease-break notifications to be acknowledged over direct TCP.");
                                TestAssertions.Equal(Smb2LeaseState.None, watcherOpen.LeaseState, "Expected the direct-TCP lease-backed open to adopt the lowered lease state.");
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second direct-TCP open not to receive a lease grant.");

                                await actorClient.CloseAsync(actorOpen, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.CloseAsync(watcherOpen, cancellationToken: token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        })
                });
        }
    }
}

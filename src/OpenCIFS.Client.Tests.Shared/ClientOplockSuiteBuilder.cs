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
    internal static class ClientOplockSuiteBuilder
    {
        /// <summary>
        /// Build the client oplock suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Oplock",
                displayName: "Client oplock-break handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Oplock",
                        caseId: "ClientAppliesUnsignedOplockBreakNotificationsAndAcknowledgesExclusiveBreaks",
                        displayName: "Client applies unsigned oplock-break notifications and acknowledges exclusive breaks",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "docs\\shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Exclusive,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 700,
                                    VolatileFileId = 701,
                                    CreateContexts = Array.Empty<byte>()
                                });

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
                                SessionId = session.SessionId!.Value,
                                Signature = new byte[16]
                            };
                            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = openState.PersistentFileId,
                                VolatileFileId = openState.VolatileFileId
                            };
                            Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(notificationHeader, notification.ToByteArray())
                            });
                            byte[] notificationPacketBytes = session.FinalizeRequestPacket(notificationPacket);
                            Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                            session.ValidateOplockBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);

                            OpenCifsClientOplockBreakNotificationResult oplockBreakResult = session.ApplyOplockBreakNotification(0, notification);

                            OpenState appliedOpenState = oplockBreakResult.OpenState;

                            Smb2OplockLevel previousOplockLevel = oplockBreakResult.PreviousOplockLevel;

                            Smb2OplockLevel newOplockLevel = oplockBreakResult.NewOplockLevel;

                            bool requiresAcknowledgment = oplockBreakResult.RequiresAcknowledgment;
                            TestAssertions.Equal(openState.PersistentFileId, appliedOpenState.PersistentFileId, "Expected oplock-break application to preserve the tracked open.");
                            TestAssertions.Equal(Smb2OplockLevel.Exclusive, previousOplockLevel, "Expected the previous oplock level to remain exclusive.");
                            TestAssertions.Equal(Smb2OplockLevel.None, newOplockLevel, "Expected the notification to lower the tracked oplock level to none.");
                            TestAssertions.True(requiresAcknowledgment, "Expected exclusive oplock breaks to require client acknowledgment.");
                            TestAssertions.Equal(Smb2OplockLevel.None, openState.OplockLevel, "Expected the tracked client open to adopt the lowered oplock level immediately.");

                            Smb2OplockBreakAcknowledgment acknowledgment = session.CreateOplockBreakAcknowledgmentRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                Smb2OplockLevel.None);
                            Smb2OplockBreakAcknowledgmentValidator.Validate(acknowledgment);
                            session.ApplyOplockBreakAcknowledgmentResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2OplockBreakResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    PersistentFileId = openState.PersistentFileId,
                                    VolatileFileId = openState.VolatileFileId
                                });
                            TestAssertions.Equal(Smb2OplockLevel.None, openState.OplockLevel, "Expected successful oplock-break acknowledgments to preserve the lowered client oplock state.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Oplock",
                        caseId: "ClientRejectsUnexpectedOrInvalidOplockBreakNotifications",
                        displayName: "Client rejects unexpected or invalid oplock-break notifications",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "docs\\shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Exclusive,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 700,
                                    VolatileFileId = 701,
                                    CreateContexts = Array.Empty<byte>()
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
                            Smb2OplockBreakNotification unsignedNotification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = openState.PersistentFileId,
                                VolatileFileId = openState.VolatileFileId
                            };
                            byte[] unsignedPacketBytes = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(wrongSessionHeader, unsignedNotification.ToByteArray())
                            }).ToByteArray();
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ValidateOplockBreakNotificationPacket(Smb2CompoundPacket.ReadFrom(unsignedPacketBytes), unsignedPacketBytes),
                                "Expected oplock-break notifications from an unrelated session to be rejected.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyOplockBreakNotification(
                                    99,
                                    new Smb2OplockBreakNotification
                                    {
                                        OplockLevel = Smb2OplockLevel.None,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId
                                    }),
                                "Expected oplock-break notifications for the wrong tree to be rejected.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyOplockBreakNotification(
                                    42,
                                    new Smb2OplockBreakNotification
                                    {
                                        OplockLevel = Smb2OplockLevel.Exclusive,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId
                                    }),
                                "Expected unsupported oplock-break downgrade shapes to be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

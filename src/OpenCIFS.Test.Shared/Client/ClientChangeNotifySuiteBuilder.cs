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
    internal static class ClientChangeNotifySuiteBuilder
    {
        /// <summary>
        /// Build the client SMB2 CHANGE_NOTIFY suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.ChangeNotify",
                displayName: "Client CHANGE_NOTIFY handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.ChangeNotify",
                        caseId: "ClientTracksAsyncChangeNotifyHeadersAndBuildsAsyncCancel",
                        displayName: "Client tracks interim async CHANGE_NOTIFY headers and builds async cancel headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            GrantCredits(session, 3);
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "watched",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Directory,
                                    PersistentFileId = 200,
                                    VolatileFileId = 201,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2Header pendingHeader = session.CreateRequestHeader(Smb2Command.ChangeNotify, treeId: 42, sessionId: session.SessionId!.Value);
                            Smb2ChangeNotifyRequest notifyRequest = session.CreateChangeNotifyRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                FileNotifyChangeFilter.FileName | FileNotifyChangeFilter.LastWrite,
                                watchTree: true,
                                outputBufferLength: 256);
                            Smb2ChangeNotifyRequestValidator.Validate(notifyRequest);

                            Smb2Header interimHeader = CreateResponseHeader(
                                pendingHeader,
                                grantedCredits: 1,
                                status: NtStatus.Pending,
                                flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                asyncId: 77);
                            byte[] interimPacketBytes = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(interimHeader, Array.Empty<byte>())
                            }).ToByteArray();
                            Smb2CompoundPacket parsedInterimPacket = Smb2CompoundPacket.ReadFrom(interimPacketBytes);

                            session.ValidateResponsePacket(parsedInterimPacket, interimPacketBytes);
                            session.ApplyResponseHeader(parsedInterimPacket.Entries[0].Header);

                            TestAssertions.Equal(3, session.AvailableCredits, "Expected the interim async CHANGE_NOTIFY response to replenish the consumed credit.");
                            TestAssertions.Equal(1, session.PendingRequestCount, "Expected the CHANGE_NOTIFY request to remain pending after the interim async response.");

                            Smb2Header cancelHeader = session.CreateCancelRequestHeader(pendingHeader.MessageId);
                            TestAssertions.Equal(Smb2HeaderFlags.AsyncCommand | Smb2HeaderFlags.Signed, cancelHeader.Flags, "Expected pending async CHANGE_NOTIFY requests in a signed session to build signed async cancel headers.");
                            TestAssertions.Equal(77UL, cancelHeader.AsyncId, "Expected the async cancel header to carry the server-assigned AsyncId.");
                            TestAssertions.Equal(0U, cancelHeader.TreeId, "Expected async cancel headers to omit the synchronous TreeId field.");

                            session.ApplyResponseHeader(
                                CreateResponseHeader(
                                    pendingHeader,
                                    grantedCredits: 0,
                                    status: NtStatus.Success,
                                    flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                    asyncId: 77));

                            TestAssertions.Equal(3, session.AvailableCredits, "Expected final async CHANGE_NOTIFY responses to avoid changing the SMB2 credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected the final async CHANGE_NOTIFY response to complete the pending request.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.ChangeNotify",
                        caseId: "ClientRejectsUnsignedFinalAsyncChangeNotifyResponses",
                        displayName: "Client accepts unsigned interim async CHANGE_NOTIFY responses and rejects unsigned final async responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            GrantCredits(session, 3);
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "watched",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Directory,
                                    PersistentFileId = 200,
                                    VolatileFileId = 201,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2Header pendingHeader = session.CreateRequestHeader(Smb2Command.ChangeNotify, treeId: 42, sessionId: session.SessionId!.Value);
                            Smb2ChangeNotifyRequest notifyRequest = session.CreateChangeNotifyRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                FileNotifyChangeFilter.FileName,
                                watchTree: true,
                                outputBufferLength: 256);
                            Smb2ChangeNotifyRequestValidator.Validate(notifyRequest);

                            Smb2Header interimHeader = CreateResponseHeader(
                                pendingHeader,
                                grantedCredits: 1,
                                status: NtStatus.Pending,
                                flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                asyncId: 88);
                            byte[] interimPacketBytes = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(interimHeader, Array.Empty<byte>())
                            }).ToByteArray();
                            Smb2CompoundPacket parsedInterimPacket = Smb2CompoundPacket.ReadFrom(interimPacketBytes);
                            session.ValidateResponsePacket(parsedInterimPacket, interimPacketBytes);
                            session.ApplyResponseHeader(parsedInterimPacket.Entries[0].Header);

                            Smb2Header signedFinalHeader = CreateResponseHeader(
                                pendingHeader,
                                grantedCredits: 0,
                                status: NtStatus.Success,
                                flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand | Smb2HeaderFlags.Signed,
                                asyncId: 88);
                            Smb2CompoundPacket signedFinalPacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(signedFinalHeader, Array.Empty<byte>())
                            });
                            byte[] signedFinalPacketBytes = session.FinalizeRequestPacket(signedFinalPacket);
                            Smb2CompoundPacket parsedSignedFinalPacket = Smb2CompoundPacket.ReadFrom(signedFinalPacketBytes);
                            session.ValidateResponsePacket(parsedSignedFinalPacket, signedFinalPacketBytes);

                            Smb2Header unsignedFinalHeader = CreateResponseHeader(
                                pendingHeader,
                                grantedCredits: 0,
                                status: NtStatus.Success,
                                flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                asyncId: 88);
                            byte[] unsignedFinalPacketBytes = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(unsignedFinalHeader, Array.Empty<byte>())
                            }).ToByteArray();
                            Smb2CompoundPacket parsedUnsignedFinalPacket = Smb2CompoundPacket.ReadFrom(unsignedFinalPacketBytes);

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ValidateResponsePacket(parsedUnsignedFinalPacket, unsignedFinalPacketBytes),
                                "Expected the client to reject unsigned final async CHANGE_NOTIFY responses in a signed SMB2 session.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.ChangeNotify",
                        caseId: "ClientAppliesChangeNotifyResultsAndRejectsInvalidEntries",
                        displayName: "Client applies CHANGE_NOTIFY results and rejects invalid relative paths",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "watched",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Directory,
                                    PersistentFileId = 300,
                                    VolatileFileId = 301,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2ChangeNotifyRequest nonRecursiveRequest = session.CreateChangeNotifyRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                FileNotifyChangeFilter.FileName,
                                watchTree: false,
                                outputBufferLength: 256);
                            FileNotifyInformation[] notifyEntries = session.ApplyChangeNotifyResult(
                                nonRecursiveRequest,
                                NtStatus.Success,
                                new Smb2ChangeNotifyResponse
                                {
                                    OutputBuffer = FileNotifyInformation.EncodeEntries(new FileNotifyInformation[]
                                    {
                                        new FileNotifyInformation
                                        {
                                            Action = FileNotifyAction.Added,
                                            FileName = "child.txt"
                                        }
                                    })
                                });
                            TestAssertions.Equal(1, notifyEntries.Length, "Expected the client to decode the returned FILE_NOTIFY_INFORMATION entry.");
                            TestAssertions.Equal("child.txt", notifyEntries[0].FileName, "Unexpected decoded CHANGE_NOTIFY path.");

                            FileNotifyInformation[] overflowEntries = session.ApplyChangeNotifyResult(
                                nonRecursiveRequest,
                                NtStatus.NotifyEnumDir,
                                new Smb2ChangeNotifyResponse());
                            TestAssertions.Equal(0, overflowEntries.Length, "Expected STATUS_NOTIFY_ENUM_DIR to surface as an empty result set.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyChangeNotifyResult(
                                    nonRecursiveRequest,
                                    NtStatus.Success,
                                    new Smb2ChangeNotifyResponse
                                    {
                                        OutputBuffer = FileNotifyInformation.EncodeEntries(new FileNotifyInformation[]
                                        {
                                            new FileNotifyInformation
                                            {
                                                Action = FileNotifyAction.Modified,
                                                FileName = "nested\\leaf.txt"
                                            }
                                        })
                                    }),
                                "Expected non-recursive CHANGE_NOTIFY responses with nested paths to be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

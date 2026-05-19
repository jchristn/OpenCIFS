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
    internal static class ServerCreditHeaderSuiteBuilder
    {
        /// <summary>
        /// Build the server SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerCreditHeaderSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Credits",
                displayName: "Server SMB2 credit and header handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerGrantsAndClampsCreditsWithinConfiguredWindow",
                        displayName: "Server grants SMB2 credits within the configured maximum and binds responses to accepted requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = "LAB-SERVER",
                                ShareName = "public",
                                SharePath = "SampleShare",
                                MaximumCredits = 4
                            });

                            TestAssertions.Equal(1, host.AvailableCredits, "Expected a new server host to start with one SMB2 credit.");

                            Smb2Header firstRequest = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 4);
                            host.ValidateAndAcceptRequestHeader(firstRequest, Smb2Command.Negotiate);
                            TestAssertions.Equal(0, host.AvailableCredits, "Expected the accepted request to consume the only available server credit.");

                            Smb2Header firstResponse = host.CreateResponseHeader(firstRequest, NtStatus.Success);
                            TestAssertions.Equal((ushort)4, firstResponse.CreditRequest, "Expected the server to grant the requested credits up to the configured limit.");
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the server credit window to grow after the response header is created.");

                            Smb2Header secondRequest = CreateRequestHeader(Smb2Command.SessionSetup, messageId: 1, creditRequest: 4);
                            host.ValidateAndAcceptRequestHeader(secondRequest, Smb2Command.SessionSetup);
                            Smb2Header secondResponse = host.CreateResponseHeader(secondRequest, NtStatus.MoreProcessingRequired, sessionId: 9);
                            TestAssertions.Equal((ushort)1, secondResponse.CreditRequest, "Expected the server to clamp granted credits once the configured maximum has been reached.");
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the server to restore the configured maximum credit window after the response header is created.");
                            TestAssertions.Equal(9UL, secondResponse.SessionId, "Expected the server to propagate the assigned session identifier into the response header.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsInvalidRequestHeaders",
                        displayName: "Server tolerates compatible credit-charge values and rejects invalid SMB2 request flags and message identifiers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost nonZeroChargeHost = CreateServerHost();
                            nonZeroChargeHost.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditCharge: 1),
                                Smb2Command.Negotiate);
                            TestAssertions.Equal(0, nonZeroChargeHost.AvailableCredits, "Expected the server to continue single-credit accounting while tolerating compatible request CreditCharge values.");

                            OpenCifsServerHost signedRequestHost = CreateServerHost();
                            signedRequestHost.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, sessionId: 7, flags: Smb2HeaderFlags.Signed),
                                Smb2Command.TreeConnect,
                                expectedSessionId: 7);

                            OpenCifsServerHost badFlagsHost = CreateServerHost();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => badFlagsHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, flags: Smb2HeaderFlags.ServerToRedir),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject unsupported SMB2 request flags.");

                            OpenCifsServerHost badMessageIdHost = CreateServerHost();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => badMessageIdHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 99),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject request message identifiers outside the current credit window.");

                            OpenCifsServerHost reusedMessageIdHost = CreateServerHost();
                            Smb2Header acceptedRequest = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2);
                            reusedMessageIdHost.ValidateAndAcceptRequestHeader(acceptedRequest, Smb2Command.Negotiate);
                            reusedMessageIdHost.CreateResponseHeader(acceptedRequest, NtStatus.Success);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => reusedMessageIdHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 0),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject reusing an SMB2 message identifier that has already been consumed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerTracksMultiCreditLargeIoHeaders",
                        displayName: "Server tracks bounded SMB 2.1 multi-credit read and write requests across credits and message-identifier ranges",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            Smb2Header negotiateHeader = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 8);
                            host.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
                            host.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb21 }
                            });
                            host.CreateResponseHeader(negotiateHeader, NtStatus.Success);
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the server credit window to grow before the multi-credit test request.");

                            Smb2Header largeReadHeader = CreateRequestHeader(Smb2Command.Read, messageId: 1, creditRequest: 4, creditCharge: 4, sessionId: 7, treeId: 42);
                            host.ValidateAndAcceptRequestHeader(largeReadHeader, Smb2Command.Read, expectedSessionId: 7, expectedTreeId: 42);
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the bounded large read request to consume four server credits.");
                            Smb2Header largeReadResponse = host.CreateResponseHeader(largeReadHeader, NtStatus.Success, sessionId: 7, treeId: 42);
                            TestAssertions.Equal((ushort)4, largeReadResponse.CreditRequest, "Expected the bounded large read response to return the requested four-credit window.");
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the bounded large read response to restore the server credit window.");

                            Smb2WriteRequest overchargedWriteRequest = new Smb2WriteRequest
                            {
                                Offset = 0,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[200000],
                                WriteChannelInfo = Array.Empty<byte>()
                            };
                            Smb2WriteRequestValidator.Validate(overchargedWriteRequest);
                            Smb2CompoundPacket overchargedWriteResponse = host.HandleCompoundRequestPacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Write, messageId: 5, creditRequest: 5, creditCharge: 5, sessionId: 7, treeId: 42),
                                        overchargedWriteRequest.ToByteArray())
                                }));
                            TestAssertions.Equal(1, overchargedWriteResponse.Entries.Count, "Expected the bounded overcharged large write packet to return a single SMB2 response entry.");
                            TestAssertions.Equal(NtStatus.AccessDenied, overchargedWriteResponse.Entries[0].Header.Status, "Expected the bounded overcharged large write packet to reach the write handler after credit validation.");
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the bounded overcharged large write response to restore the consumed server credits.");

                            host.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.Echo, messageId: 10, sessionId: 7),
                                Smb2Command.Echo,
                                expectedSessionId: 7);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsInvalidLargeIoCreditShapes",
                        displayName: "Server rejects invalid bounded SMB 2.1 multi-credit large-I/O header and payload combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost legacyHost = CreateServerHost();
                            legacyHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002 }
                            });
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => legacyHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Read, messageId: 0, creditCharge: 2, sessionId: 7, treeId: 42),
                                    Smb2Command.Read,
                                    expectedSessionId: 7,
                                    expectedTreeId: 42),
                                "Expected the server to reject multi-credit large-I/O headers before SMB 2.1 negotiation.");

                            OpenCifsServerHost underchargedHost = CreateServerHost();
                            underchargedHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb21 }
                            });
                            Smb2WriteRequest underchargedWriteRequest = new Smb2WriteRequest
                            {
                                Offset = 0,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[200000],
                                WriteChannelInfo = Array.Empty<byte>()
                            };
                            Smb2WriteRequestValidator.Validate(underchargedWriteRequest);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => underchargedHost.HandleCompoundRequestPacket(
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Write, messageId: 0, creditCharge: 1, sessionId: 7, treeId: 42),
                                            underchargedWriteRequest.ToByteArray())
                                    })),
                                "Expected the server packet surface to reject large SMB2 write requests whose CreditCharge is smaller than the payload length requires.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerCancelsAcceptedPendingRequestsWithoutConsumingCredits",
                        displayName: "Server cancels accepted pending requests without consuming an additional credit and returns a cancelled target response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2Header pendingHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, sessionId: sessionId);
                            host.ValidateAndAcceptRequestHeader(pendingHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            TestAssertions.Equal(0, host.AvailableCredits, "Expected the accepted pending request to consume the currently granted server credit.");

                            OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                new Smb2Header
                                {
                                    CreditCharge = 0,
                                    Status = NtStatus.Success,
                                    Command = Smb2Command.Cancel,
                                    CreditRequest = 0,
                                    Flags = Smb2HeaderFlags.None,
                                    NextCommand = 0,
                                    MessageId = pendingHeader.MessageId,
                                    SessionId = sessionId,
                                    Signature = new byte[16]
                                },
                                new Smb2CancelRequest());

                            TestAssertions.True(cancelResult.WasCancelled, "Expected the pending SMB2 echo request to be cancelled.");
                            TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected successful cancellation to emit a target response header.");
                            TestAssertions.Equal(Smb2Command.Echo, cancelResult.TargetResponseHeader!.Command, "Expected the cancelled target response to preserve the original command.");
                            TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader.Status, "Expected successful cancellation to fail the target request with STATUS_CANCELLED.");
                            Smb2EchoResponse cancelledEchoResponse = Smb2EchoResponse.ReadFrom(cancelResult.TargetResponsePayload);
                            Smb2EchoResponseValidator.Validate(cancelledEchoResponse);
                            TestAssertions.Equal(3, host.AvailableCredits, "Expected the cancelled target response to restore the requested SMB2 credit window.");

                            OpenCifsServerCancelResult missingResult = host.HandleCancel(
                                new Smb2Header
                                {
                                    CreditCharge = 0,
                                    Status = NtStatus.Success,
                                    Command = Smb2Command.Cancel,
                                    CreditRequest = 0,
                                    Flags = Smb2HeaderFlags.None,
                                    NextCommand = 0,
                                    MessageId = pendingHeader.MessageId,
                                    SessionId = sessionId,
                                    Signature = new byte[16]
                                },
                                new Smb2CancelRequest());
                            TestAssertions.False(missingResult.WasCancelled, "Expected cancelling an already completed target request to become a no-op.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.CreateResponseHeader(pendingHeader, NtStatus.Success, sessionId: sessionId),
                                "Expected cancelled target requests to be removed from the pending-request table.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerValidatesSignedAuthenticatedPacketsAndAcceptsSignedCancel",
                        displayName: "Server validates signed authenticated SMB2 packets and accepts signed cancel requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            AuthenticatedSigningContext signingContext = AuthenticateSessionAndGetSigningKey(host);
                            ulong sessionId = signingContext.SessionId;
                            byte[] signingKey = signingContext.SigningKey;
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            TestAssertions.True((parsedEchoPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated echo requests to carry the SMB2 Signed flag.");
                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            Smb2CancelRequest cancelRequest = new Smb2CancelRequest();
                            Smb2CancelRequestValidator.Validate(cancelRequest);
                            Smb2Header cancelHeader = CreateRequestHeader(Smb2Command.Cancel, messageId: echoHeader.MessageId, creditRequest: 1, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] cancelBytes = CreateSignedPacketBytes(cancelHeader, cancelRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedCancelPacket = Smb2CompoundPacket.ReadFrom(cancelBytes);

                            TestAssertions.True((parsedCancelPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign SMB2 cancel headers.");
                            host.ValidateRequestPacket(parsedCancelPacket, cancelBytes);

                            OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                parsedCancelPacket.Entries[0].Header,
                                Smb2CancelRequest.ReadFrom(parsedCancelPacket.Entries[0].Payload));
                            TestAssertions.True(cancelResult.WasCancelled, "Expected the server to cancel the signed pending echo request.");
                            TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected signed cancel handling to emit the cancelled target response.");
                            TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader!.Status, "Expected signed cancel handling to fail the target request with STATUS_CANCELLED.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCancel(
                                    CreateRequestHeader(Smb2Command.Cancel, messageId: echoHeader.MessageId, creditRequest: 2, flags: Smb2HeaderFlags.Signed, sessionId: sessionId),
                                    new Smb2CancelRequest()),
                                "Expected cancel requests with CreditRequest values above 1 to remain rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsUnsignedOrTamperedSignedAuthenticatedPackets",
                        displayName: "Server rejects authenticated SMB2 packets that omit or violate required signatures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            AuthenticatedSigningContext signingContext = AuthenticateSessionAndGetSigningKey(host);
                            ulong sessionId = signingContext.SessionId;
                            byte[] signingKey = signingContext.SigningKey;
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header signedEchoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] signedEchoBytes = CreateSignedPacketBytes(signedEchoHeader, echoRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedSignedEchoPacket = Smb2CompoundPacket.ReadFrom(signedEchoBytes);

                            Smb2Header unsignedEchoHeader = new Smb2Header
                            {
                                CreditCharge = parsedSignedEchoPacket.Entries[0].Header.CreditCharge,
                                Status = parsedSignedEchoPacket.Entries[0].Header.Status,
                                Command = parsedSignedEchoPacket.Entries[0].Header.Command,
                                CreditRequest = parsedSignedEchoPacket.Entries[0].Header.CreditRequest,
                                Flags = parsedSignedEchoPacket.Entries[0].Header.Flags & ~Smb2HeaderFlags.Signed,
                                NextCommand = parsedSignedEchoPacket.Entries[0].Header.NextCommand,
                                MessageId = parsedSignedEchoPacket.Entries[0].Header.MessageId,
                                ProcessId = parsedSignedEchoPacket.Entries[0].Header.ProcessId,
                                TreeId = parsedSignedEchoPacket.Entries[0].Header.TreeId,
                                AsyncId = parsedSignedEchoPacket.Entries[0].Header.AsyncId,
                                SessionId = parsedSignedEchoPacket.Entries[0].Header.SessionId,
                                Signature = new byte[16]
                            };
                            Smb2CompoundPacket unsignedEchoPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(unsignedEchoHeader, echoRequest.ToByteArray())
                                });
                            byte[] unsignedEchoBytes = unsignedEchoPacket.ToByteArray();
                            Smb2CompoundPacket parsedUnsignedEchoPacket = Smb2CompoundPacket.ReadFrom(unsignedEchoBytes);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedUnsignedEchoPacket, unsignedEchoBytes),
                                "Expected the server to reject authenticated SMB2 requests that omit the required Signed flag.");

                            byte[] tamperedEchoBytes = (byte[])signedEchoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject authenticated SMB2 requests whose signatures no longer verify.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerUsesAesCmacForSignedPacketsWhenNegotiatedSmb302",
                        displayName: "Server validates and emits AES-CMAC SMB2 signatures when SMB 3.0.2 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            AuthenticatedSigningContext signingContext = AuthenticateSessionAndGetSigningKey(
                                host,
                                dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 },
                                expectedDialect: SmbDialect.Smb302);

                            ulong sessionId = signingContext.SessionId;

                            byte[] signingKey = signingContext.SigningKey;
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey, SmbDialect.Smb302);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            byte[] tamperedEchoBytes = (byte[])echoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject tampered AES-CMAC signed SMB2 requests.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedEchoPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponsePacket.Entries[0].Header.Signature),
                                "Expected the SMB 3.0.2 echo response signature to verify with AES-CMAC.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerUsesAesCmacForSignedPacketsWhenNegotiatedSmb30",
                        displayName: "Server validates and emits AES-CMAC SMB2 signatures when SMB 3.0 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            AuthenticatedSigningContext signingContext = AuthenticateSessionAndGetSigningKey(
                                host,
                                dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30 },
                                expectedDialect: SmbDialect.Smb30);

                            ulong sessionId = signingContext.SessionId;

                            byte[] signingKey = signingContext.SigningKey;
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey, SmbDialect.Smb30);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            byte[] tamperedEchoBytes = (byte[])echoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject tampered AES-CMAC signed SMB 3.0 requests.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedEchoPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponsePacket.Entries[0].Header.Signature),
                                "Expected the SMB 3.0 echo response signature to verify with AES-CMAC.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

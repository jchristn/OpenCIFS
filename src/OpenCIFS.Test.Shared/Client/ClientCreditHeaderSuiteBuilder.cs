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
    internal static class ClientCreditHeaderSuiteBuilder
    {
        /// <summary>
        /// Build the client SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Credits",
                displayName: "Client SMB2 credit and header handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientTracksCreditWindowAndPendingRequests",
                        displayName: "Client tracks SMB2 credits, message identifiers, and out-of-order response completion",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            TestAssertions.Equal(1, session.AvailableCredits, "Expected a newly constructed client session to start with one SMB2 credit.");

                            Smb2Header negotiateHeader = session.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: 4);
                            TestAssertions.Equal((ushort)0, negotiateHeader.CreditCharge, "Expected SMB 2.0.2 request headers to leave CreditCharge at zero.");
                            TestAssertions.Equal(0UL, negotiateHeader.MessageId, "Expected the first SMB2 request to consume message identifier zero.");
                            TestAssertions.Equal(0, session.AvailableCredits, "Expected the outbound request to consume the only available credit.");
                            TestAssertions.Equal(1, session.PendingRequestCount, "Expected the outbound request to remain pending until a response header is applied.");

                            session.ApplyResponseHeader(CreateResponseHeader(negotiateHeader, grantedCredits: 4));
                            TestAssertions.Equal(4, session.AvailableCredits, "Expected the negotiate response to replenish the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected the negotiate request to complete after the response header is applied.");

                            Smb2Header firstPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, creditRequest: 1);
                            Smb2Header secondPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, creditRequest: 1);
                            TestAssertions.Equal(1UL, firstPendingHeader.MessageId, "Expected the client to allocate the next SMB2 message identifier.");
                            TestAssertions.Equal(2UL, secondPendingHeader.MessageId, "Expected the client to continue allocating consecutive message identifiers.");
                            TestAssertions.Equal(2, session.PendingRequestCount, "Expected both SMB2 requests to remain pending.");

                            session.ApplyResponseHeader(CreateResponseHeader(secondPendingHeader, grantedCredits: 1));
                            session.ApplyResponseHeader(CreateResponseHeader(firstPendingHeader, grantedCredits: 1));
                            TestAssertions.Equal(4, session.AvailableCredits, "Expected out-of-order responses to restore the full client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected both pending requests to complete after their response headers arrive.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientRejectsInvalidResponseHeaders",
                        displayName: "Client tolerates compatible credit-charge values and rejects malformed or mismatched SMB2 response headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession missingFlagSession = CreateNegotiatedClient();
                            Smb2Header missingFlagRequest = missingFlagSession.CreateRequestHeader(Smb2Command.Negotiate);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => missingFlagSession.ApplyResponseHeader(CreateResponseHeader(missingFlagRequest, flags: Smb2HeaderFlags.None)),
                                "Expected the client to reject response headers without the ServerToRedir flag.");

                            OpenCifsClientSession unknownMessageSession = CreateNegotiatedClient();
                            unknownMessageSession.CreateRequestHeader(Smb2Command.Negotiate);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => unknownMessageSession.ApplyResponseHeader(new Smb2Header
                                {
                                    CreditCharge = 0,
                                    Status = NtStatus.Success,
                                    Command = Smb2Command.Negotiate,
                                    CreditRequest = 1,
                                    Flags = Smb2HeaderFlags.ServerToRedir,
                                    NextCommand = 0,
                                    MessageId = 99,
                                    Signature = new byte[16]
                                }),
                                "Expected the client to reject response headers for unknown SMB2 message identifiers.");

                            OpenCifsClientSession nonZeroChargeSession = CreateNegotiatedClient();
                            Smb2Header nonZeroChargeRequest = nonZeroChargeSession.CreateRequestHeader(Smb2Command.Negotiate);
                            nonZeroChargeSession.ApplyResponseHeader(CreateResponseHeader(nonZeroChargeRequest, grantedCredits: 1, creditCharge: 1));
                            TestAssertions.Equal(1, nonZeroChargeSession.AvailableCredits, "Expected the client to tolerate compatible response CreditCharge values while still applying granted credits.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientRejectsRequestHeadersWhenCreditsAreExhausted",
                        displayName: "Client rejects new SMB2 request headers when the local credit window is exhausted",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            Smb2Header firstRequest = session.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: 2);
                            TestAssertions.Equal(0, session.AvailableCredits, "Expected the first SMB2 request to consume the only available local credit.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateRequestHeader(Smb2Command.SessionSetup),
                                "Expected the client to reject allocating another SMB2 request header before credits are restored.");

                            session.ApplyResponseHeader(CreateResponseHeader(firstRequest, grantedCredits: 2));
                            TestAssertions.Equal(2, session.AvailableCredits, "Expected the negotiated client credit window to recover after the response header is applied.");

                            Smb2Header recoveredRequest = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            TestAssertions.Equal(1UL, recoveredRequest.MessageId, "Expected the client to continue allocating SMB2 message identifiers after the credit window recovers.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientTracksMultiCreditLargeIoHeaders",
                        displayName: "Client tracks bounded SMB 2.1 multi-credit read and write requests across the local credit and message-id windows",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient(SmbDialect.Smb21);
                            GrantCredits(session, 20);

                            Smb2Header largeReadHeader = session.CreateRequestHeader(
                                Smb2Command.Read,
                                creditRequest: 4,
                                sessionId: 9,
                                creditCharge: 4);
                            TestAssertions.Equal((ushort)4, largeReadHeader.CreditCharge, "Expected the bounded SMB 2.1 large read request to carry a four-credit charge.");
                            TestAssertions.Equal(1UL, largeReadHeader.MessageId, "Expected the first multi-credit SMB2 request to begin after the negotiate helper consumes message identifier zero.");
                            TestAssertions.Equal(16, session.AvailableCredits, "Expected the bounded large read request to consume four local credits.");
                            session.ApplyResponseHeader(CreateResponseHeader(largeReadHeader, grantedCredits: 4));
                            TestAssertions.Equal(20, session.AvailableCredits, "Expected the large read response to restore the requested four-credit window.");

                            Smb2Header largeWriteHeader = session.CreateRequestHeader(
                                Smb2Command.Write,
                                creditRequest: 3,
                                sessionId: 9,
                                creditCharge: 3);
                            TestAssertions.Equal((ushort)3, largeWriteHeader.CreditCharge, "Expected the bounded SMB 2.1 large write request to carry a three-credit charge.");
                            TestAssertions.Equal(5UL, largeWriteHeader.MessageId, "Expected the next multi-credit SMB2 request to skip the previously consumed message-identifier range.");
                            TestAssertions.Equal(17, session.AvailableCredits, "Expected the bounded large write request to consume three local credits.");
                            session.ApplyResponseHeader(CreateResponseHeader(largeWriteHeader, grantedCredits: 3));

                            Smb2Header followOnHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: 9);
                            TestAssertions.Equal(8UL, followOnHeader.MessageId, "Expected subsequent SMB2 requests to continue after the consumed multi-credit range.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientRejectsInvalidLargeIoCreditShapes",
                        displayName: "Client rejects multi-credit large-I/O requests outside the bounded SMB 2.1 credit and local-window rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession legacySession = CreateNegotiatedClient();
                            GrantCredits(legacySession, 4);
                            TestAssertions.Throws<InvalidOperationException>(
                                () => legacySession.CreateRequestHeader(Smb2Command.Read, creditRequest: 2, sessionId: 9, creditCharge: 2),
                                "Expected the client to reject multi-credit large-I/O headers before SMB 2.1 is negotiated.");

                            OpenCifsClientSession constrainedSession = CreateNegotiatedClient(SmbDialect.Smb21);
                            GrantCredits(constrainedSession, 2);
                            TestAssertions.Throws<InvalidOperationException>(
                                () => constrainedSession.CreateRequestHeader(Smb2Command.Write, creditRequest: 3, sessionId: 9, creditCharge: 3),
                                "Expected the client to reject large-I/O headers when the local credit window is too small for the requested charge.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientCreatesCancelHeadersWithoutConsumingCredits",
                        displayName: "Client creates bounded SMB2 cancel headers without consuming credits or completing pending requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            GrantCredits(session, 3);

                            Smb2Header pendingHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: session.SessionId!.Value);
                            int availableCreditsBeforeCancel = session.AvailableCredits;
                            int pendingRequestsBeforeCancel = session.PendingRequestCount;

                            Smb2CancelRequest cancelRequest = session.CreateCancelRequest();
                            Smb2CancelRequestValidator.Validate(cancelRequest);
                            Smb2Header cancelHeader = session.CreateCancelRequestHeader(pendingHeader.MessageId);

                            TestAssertions.Equal(Smb2Command.Cancel, cancelHeader.Command, "Expected cancel headers to target SMB2 CANCEL.");
                            TestAssertions.Equal(pendingHeader.MessageId, cancelHeader.MessageId, "Expected cancel headers to reuse the pending request message identifier.");
                            TestAssertions.Equal(session.SessionId!.Value, cancelHeader.SessionId, "Expected cancel headers to preserve the pending request session identifier.");
                            TestAssertions.Equal((ushort)0, cancelHeader.CreditRequest, "Expected bounded SMB2 cancel headers to request zero credits.");
                            TestAssertions.Equal(availableCreditsBeforeCancel, session.AvailableCredits, "Expected bounded SMB2 cancel headers to leave the client credit window unchanged.");
                            TestAssertions.Equal(pendingRequestsBeforeCancel, session.PendingRequestCount, "Expected bounded SMB2 cancel headers to leave the pending-request table unchanged.");

                            session.ApplyResponseHeader(CreateResponseHeader(pendingHeader, grantedCredits: 1, status: NtStatus.Cancelled));
                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyEchoResult(NtStatus.Cancelled, new Smb2EchoResponse()),
                                "Cancelled echo target responses should surface as failed operations on the client.");
                            TestAssertions.Equal(3, session.AvailableCredits, "Expected the cancelled target response to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected the cancelled target response to complete the pending request.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientSignsAuthenticatedPacketsAndAcceptsSignedResponses",
                        displayName: "Client signs authenticated SMB2 packets and accepts signed echo responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            AuthenticatedLoopbackPair loopbackPair = CreateAuthenticatedLoopbackPair();

                            OpenCifsServerHost host = loopbackPair.Host;

                            OpenCifsClientSession session = loopbackPair.Client;

                            ulong sessionId = loopbackPair.SessionId;
                            Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                            Smb2Header echoHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                });
                            byte[] requestBytes = session.FinalizeRequestPacket(requestPacket);
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated client requests to carry the SMB2 Signed flag.");
                            TestAssertions.True(Array.Exists(parsedRequestPacket.Entries[0].Header.Signature, value => value != 0), "Expected authenticated client requests to carry a non-zero SMB2 signature.");

                            host.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                            host.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                            TestAssertions.True((parsedResponsePacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated echo responses to carry the SMB2 Signed flag.");

                            session.ValidateResponsePacket(parsedResponsePacket, responseBytes);
                            session.ApplyResponseHeader(parsedResponsePacket.Entries[0].Header);
                            session.ApplyEchoResult(parsedResponsePacket.Entries[0].Header.Status, Smb2EchoResponse.ReadFrom(parsedResponsePacket.Entries[0].Payload));
                            TestAssertions.Equal(1, session.AvailableCredits, "Expected the signed echo response to restore the consumed client credit.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected the signed echo response to complete the pending request.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientSignsAuthenticatedPacketsWithAesCmacWhenNegotiatedSmb302",
                        displayName: "Client signs authenticated SMB2 packets with AES-CMAC when SMB 3.0.2 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            AuthenticatedLoopbackPair loopbackPair = CreateAuthenticatedLoopbackPair(SmbDialect.Smb302);

                            OpenCifsServerHost host = loopbackPair.Host;

                            OpenCifsClientSession session = loopbackPair.Client;

                            ulong sessionId = loopbackPair.SessionId;
                            Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                            Smb2Header echoHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                });
                            byte[] requestBytes = session.FinalizeRequestPacket(requestPacket);
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                            TestAssertions.Equal(SmbDialect.Smb302, session.NegotiatedDialect!.Value, "Expected the loopback client session to negotiate SMB 3.0.2.");
                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated SMB 3.0.2 client requests to carry the SMB2 Signed flag.");

                            host.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                            host.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                            session.ValidateResponsePacket(parsedResponsePacket, responseBytes);
                            session.ApplyResponseHeader(parsedResponsePacket.Entries[0].Header);
                            session.ApplyEchoResult(parsedResponsePacket.Entries[0].Header.Status, Smb2EchoResponse.ReadFrom(parsedResponsePacket.Entries[0].Payload));
                            TestAssertions.Equal(1, session.AvailableCredits, "Expected the AES-CMAC-signed echo response to restore the consumed client credit.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientSignsAuthenticatedPacketsWithAesCmacWhenNegotiatedSmb30",
                        displayName: "Client signs authenticated SMB2 packets with AES-CMAC when SMB 3.0 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            AuthenticatedLoopbackPair loopbackPair = CreateAuthenticatedLoopbackPair(SmbDialect.Smb30);

                            OpenCifsServerHost host = loopbackPair.Host;

                            OpenCifsClientSession session = loopbackPair.Client;

                            ulong sessionId = loopbackPair.SessionId;
                            Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                            Smb2Header echoHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                });
                            byte[] requestBytes = session.FinalizeRequestPacket(requestPacket);
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                            TestAssertions.Equal(SmbDialect.Smb30, session.NegotiatedDialect!.Value, "Expected the loopback client session to negotiate SMB 3.0.");
                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated SMB 3.0 client requests to carry the SMB2 Signed flag.");

                            host.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                            host.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                            session.ValidateResponsePacket(parsedResponsePacket, responseBytes);
                            session.ApplyResponseHeader(parsedResponsePacket.Entries[0].Header);
                            session.ApplyEchoResult(parsedResponsePacket.Entries[0].Header.Status, Smb2EchoResponse.ReadFrom(parsedResponsePacket.Entries[0].Payload));
                            TestAssertions.Equal(1, session.AvailableCredits, "Expected the SMB 3.0 AES-CMAC-signed echo response to restore the consumed client credit.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Credits",
                        caseId: "ClientRejectsUnsignedOrTamperedSignedResponses",
                        displayName: "Client rejects missing or tampered SMB2 signatures on authenticated echo responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            {
                                AuthenticatedLoopbackPair loopbackPair = CreateAuthenticatedLoopbackPair();
                                OpenCifsServerHost host = loopbackPair.Host;
                                OpenCifsClientSession session = loopbackPair.Client;
                                ulong sessionId = loopbackPair.SessionId;
                                Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                                Smb2Header echoHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                    });
                                byte[] requestBytes = session.FinalizeRequestPacket(requestPacket);
                                Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                                host.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                                host.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                                OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                                Smb2Header unsignedResponseHeader = host.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                                unsignedResponseHeader.Flags &= ~Smb2HeaderFlags.Signed;
                                Smb2CompoundPacket unsignedResponsePacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(unsignedResponseHeader, echoResult.Response.ToByteArray())
                                    });
                                byte[] unsignedResponseBytes = unsignedResponsePacket.ToByteArray();
                                Smb2CompoundPacket parsedUnsignedResponsePacket = Smb2CompoundPacket.ReadFrom(unsignedResponseBytes);

                                TestAssertions.Throws<OpenCifsClientProtocolException>(
                                    () => session.ValidateResponsePacket(parsedUnsignedResponsePacket, unsignedResponseBytes),
                                    "Expected the client to reject authenticated echo responses that omit the required SMB2 Signed flag.");
                            }

                            {
                                AuthenticatedLoopbackPair loopbackPair = CreateAuthenticatedLoopbackPair();
                                OpenCifsServerHost host = loopbackPair.Host;
                                OpenCifsClientSession session = loopbackPair.Client;
                                ulong sessionId = loopbackPair.SessionId;
                                Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                                Smb2Header echoHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                    });
                                byte[] requestBytes = session.FinalizeRequestPacket(requestPacket);
                                Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                                host.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                                host.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                                OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                                Smb2Header responseHeader = host.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                                Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                    });
                                byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                                byte[] tamperedResponseBytes = (byte[])responseBytes.Clone();
                                tamperedResponseBytes[tamperedResponseBytes.Length - 1] ^= 0x01;
                                Smb2CompoundPacket parsedTamperedResponsePacket = Smb2CompoundPacket.ReadFrom(tamperedResponseBytes);

                                TestAssertions.Throws<OpenCifsClientProtocolException>(
                                    () => session.ValidateResponsePacket(parsedTamperedResponsePacket, tamperedResponseBytes),
                                    "Expected the client to reject authenticated echo responses whose SMB2 signature no longer verifies.");
                            }

                            return Task.CompletedTask;
                        })
                });
        }
    }
}

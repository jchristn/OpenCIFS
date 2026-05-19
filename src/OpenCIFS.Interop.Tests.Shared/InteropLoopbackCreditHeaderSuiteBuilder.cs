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
    internal static class InteropLoopbackCreditHeaderSuiteBuilder
    {
        /// <summary>
        /// Build the loopback SMB2 compounding suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor LoopbackCreditHeaderSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackCredits",
                displayName: "Loopback SMB2 credit and header coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerMaintainCreditsAcrossHeaderWrappedLifecycle",
                        displayName: "Client and server maintain the SMB2 credit window across header-wrapped negotiate, session, tree, and file-I/O requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropCredits_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();

                                Smb2Header negotiateHeader = client.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: 4);
                                Smb2NegotiateRequest negotiateRequest = client.CreateNegotiateRequest();
                                server.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
                                Smb2NegotiateResponse negotiateResponse = server.HandleNegotiate(negotiateRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(negotiateHeader, NtStatus.Success));
                                client.ApplyNegotiateResponse(negotiateResponse);
                                TestAssertions.Equal(4, client.AvailableCredits, "Expected negotiate to expand the loopback client credit window.");

                                Smb2Header initialSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                                Smb2SessionSetupRequest initialSessionRequest = client.CreateSessionSetupRequest(credential);
                                server.ValidateAndAcceptRequestHeader(initialSessionHeader, Smb2Command.SessionSetup);
                                OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, initialSessionRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(initialSessionHeader, challengeResult.Status, sessionId: challengeResult.SessionId));

                                Smb2SessionSetupRequest authenticateSessionRequest = client.CreateSessionAuthenticateRequest(
                                    credential,
                                    challengeResult.SessionId,
                                    challengeResult.Status,
                                    challengeResult.Response);
                                Smb2Header authenticateSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResult.SessionId);
                                server.ValidateAndAcceptRequestHeader(authenticateSessionHeader, Smb2Command.SessionSetup, expectedSessionId: challengeResult.SessionId);
                                OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateSessionRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(authenticateSessionHeader, successResult.Status, sessionId: successResult.SessionId));
                                client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: client.SessionId!.Value);
                                Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("public");
                                server.ValidateAndAcceptRequestHeader(treeConnectHeader, Smb2Command.TreeConnect, expectedSessionId: client.SessionId!.Value);
                                OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(client.SessionId.Value, treeConnectRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: client.SessionId.Value, treeId: treeConnectResult.TreeId));
                                client.ApplyTreeConnectResult("public", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                                uint treeId = treeConnectResult.TreeId;
                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "credits.txt");
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId.Value, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                OpenState openState = client.ApplyCreateResult(treeId, "credits.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("credit path");
                                Smb2Header writeHeader = client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: client.SessionId!.Value);
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                server.ValidateAndAcceptRequestHeader(writeHeader, Smb2Command.Write, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(client.SessionId.Value, treeId, writeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(writeHeader, writeResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response);

                                Smb2Header readHeader = client.CreateRequestHeader(Smb2Command.Read, treeId, sessionId: client.SessionId!.Value);
                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length);
                                server.ValidateAndAcceptRequestHeader(readHeader, Smb2Command.Read, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = server.HandleRead(client.SessionId.Value, treeId, readRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(readHeader, readResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                byte[] readBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readResult.Status, readResult.Response);
                                TestAssertions.SequenceEqual(payload, readBytes, "Expected the header-wrapped loopback read to return the written payload.");

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId!.Value);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(client.SessionId.Value, treeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);

                                Smb2Header treeDisconnectHeader = client.CreateRequestHeader(Smb2Command.TreeDisconnect, treeId, sessionId: client.SessionId!.Value);
                                Smb2TreeDisconnectRequest treeDisconnectRequest = client.CreateTreeDisconnectRequest(treeId);
                                server.ValidateAndAcceptRequestHeader(treeDisconnectHeader, Smb2Command.TreeDisconnect, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = server.HandleTreeDisconnect(client.SessionId.Value, treeId, treeDisconnectRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(treeDisconnectHeader, treeDisconnectResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyTreeDisconnectResult(treeId, treeDisconnectResult.Status, treeDisconnectResult.Response);

                                Smb2Header logoffHeader = client.CreateRequestHeader(Smb2Command.Logoff, sessionId: client.SessionId!.Value);
                                Smb2LogoffRequest logoffRequest = client.CreateLogoffRequest();
                                server.ValidateAndAcceptRequestHeader(logoffHeader, Smb2Command.Logoff, expectedSessionId: client.SessionId!.Value);
                                OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = server.HandleLogoff(client.SessionId.Value, logoffRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(logoffHeader, logoffResult.Status, sessionId: client.SessionId.Value));
                                client.ApplyLogoffResult(logoffResult.Status, logoffResult.Response);

                                TestAssertions.Equal(4, client.AvailableCredits, "Expected the loopback client to keep a stable SMB2 credit window when each request asks for one replacement credit.");
                                TestAssertions.Equal(4, server.AvailableCredits, "Expected the loopback server to keep a stable SMB2 credit window when each request asks for one replacement credit.");
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected every header-wrapped loopback request to complete.");
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
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerRejectBadMessageIdAfterCreditGrant",
                        displayName: "Client and server loopback reject a request header that reuses a consumed SMB2 message identifier",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();

                            Smb2Header negotiateHeader = client.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: 3);
                            server.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
                            client.ApplyResponseHeader(server.CreateResponseHeader(negotiateHeader, NtStatus.Success));

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => server.ValidateAndAcceptRequestHeader(
                                    new Smb2Header
                                    {
                                        CreditCharge = 0,
                                        Status = NtStatus.Success,
                                        Command = Smb2Command.SessionSetup,
                                        CreditRequest = 1,
                                        Flags = Smb2HeaderFlags.None,
                                        NextCommand = 0,
                                        MessageId = 0,
                                        Signature = new byte[16]
                                    },
                                    Smb2Command.SessionSetup),
                                "Expected the loopback server to reject reusing a consumed SMB2 message identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerRoundTripLargeIoWithMultiCreditHeaders",
                        displayName: "Client and server loopback round-trip bounded SMB 2.1 large I/O with matching multi-credit headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsLoopbackLargeIo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 20);
                                byte[] payload = CreateLargePayloadBytes(200000);

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "large.bin");
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId.Value, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                OpenState openState = client.ApplyCreateResult(treeId, "large.bin", createResult.Status, createResult.Response);

                                ushort writeCredits = client.GetRequiredReadWriteCredits(checked((uint)payload.Length));
                                Smb2Header writeHeader = client.CreateRequestHeader(
                                    Smb2Command.Write,
                                    treeId,
                                    creditRequest: writeCredits,
                                    sessionId: client.SessionId!.Value,
                                    creditCharge: client.GetReadWriteCreditCharge(checked((uint)payload.Length)));
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                server.ValidateAndAcceptRequestHeader(writeHeader, Smb2Command.Write, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(client.SessionId.Value, treeId, writeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(writeHeader, writeResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response);

                                ushort readCredits = client.GetRequiredReadWriteCredits(checked((uint)payload.Length));
                                Smb2Header readHeader = client.CreateRequestHeader(
                                    Smb2Command.Read,
                                    treeId,
                                    creditRequest: readCredits,
                                    sessionId: client.SessionId!.Value,
                                    creditCharge: client.GetReadWriteCreditCharge(checked((uint)payload.Length)));
                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, checked((uint)payload.Length), 0, minimumCount: checked((uint)payload.Length));
                                server.ValidateAndAcceptRequestHeader(readHeader, Smb2Command.Read, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = server.HandleRead(client.SessionId.Value, treeId, readRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(readHeader, readResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                byte[] actualBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readResult.Status, readResult.Response);
                                TestAssertions.SequenceEqual(payload, actualBytes, "Expected the header-wrapped loopback large-I/O path to round-trip the payload.");
                                TestAssertions.Equal(20, client.AvailableCredits, "Expected the loopback large-I/O response path to preserve the expanded client credit window.");
                                TestAssertions.Equal(20, server.AvailableCredits, "Expected the loopback large-I/O response path to preserve the expanded server credit window.");
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
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerCancelAcceptedPendingEchoRequest",
                        displayName: "Client and server loopback cancel an accepted pending echo request and return STATUS_CANCELLED on the target response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 3);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            server.ValidateAndAcceptRequestHeader(echoHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            Smb2EchoRequestValidator.Validate(echoRequest);

                            Smb2Header cancelHeader = client.CreateCancelRequestHeader(echoHeader.MessageId);
                            OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                            TestAssertions.True(cancelResult.WasCancelled, "Expected loopback cancel handling to cancel the accepted pending echo request.");
                            TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected successful loopback cancellation to emit the cancelled target response.");

                            Smb2Header cancelledTargetHeader = cancelResult.TargetResponseHeader!;
                            client.ApplyResponseHeader(cancelledTargetHeader);
                            Smb2EchoResponse cancelledEchoResponse = Smb2EchoResponse.ReadFrom(cancelResult.TargetResponsePayload);
                            TestAssertions.Throws<InvalidOperationException>(
                                () => client.ApplyEchoResult(cancelledTargetHeader.Status, cancelledEchoResponse),
                                "Expected the loopback client to surface cancelled echo target responses as failures.");
                            TestAssertions.Equal(3, client.AvailableCredits, "Expected cancelling the pending loopback target request to restore the client credit window.");
                            TestAssertions.Equal(3, server.AvailableCredits, "Expected cancelling the pending loopback target request to restore the server credit window.");
                            TestAssertions.Equal(0, client.PendingRequestCount, "Expected the cancelled loopback target request to leave no pending client request state.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerValidateSignedEchoPacketsAfterAuthentication",
                        displayName: "Client and server loopback validate signed SMB2 echo packets after authentication",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 3);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                });
                            byte[] requestBytes = client.FinalizeRequestPacket(requestPacket);
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected the authenticated loopback echo request to carry the SMB2 Signed flag.");

                            server.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                            server.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = server.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = server.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                            TestAssertions.True((parsedResponsePacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected the authenticated loopback echo response to carry the SMB2 Signed flag.");

                            client.ValidateResponsePacket(parsedResponsePacket, responseBytes);
                            client.ApplyResponseHeader(parsedResponsePacket.Entries[0].Header);
                            client.ApplyEchoResult(parsedResponsePacket.Entries[0].Header.Status, Smb2EchoResponse.ReadFrom(parsedResponsePacket.Entries[0].Payload));
                            TestAssertions.Equal(3, client.AvailableCredits, "Expected signed loopback echo to preserve the authenticated client credit window.");
                            TestAssertions.Equal(3, server.AvailableCredits, "Expected signed loopback echo to preserve the authenticated server credit window.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCredits",
                        caseId: "ClientAndServerRejectTamperedSignedEchoResponseAfterAuthentication",
                        displayName: "Client and server loopback reject a tampered signed SMB2 echo response after authentication",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 3);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                                });
                            byte[] requestBytes = client.FinalizeRequestPacket(requestPacket);
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestBytes);

                            server.ValidateRequestPacket(parsedRequestPacket, requestBytes);
                            server.ValidateAndAcceptRequestHeader(parsedRequestPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = server.CreateResponseHeader(parsedRequestPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = server.FinalizeResponsePacket(responsePacket);
                            byte[] tamperedResponseBytes = (byte[])responseBytes.Clone();
                            tamperedResponseBytes[tamperedResponseBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedResponsePacket = Smb2CompoundPacket.ReadFrom(tamperedResponseBytes);

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => client.ValidateResponsePacket(parsedTamperedResponsePacket, tamperedResponseBytes),
                                "Expected the loopback client to reject tampered signed SMB2 echo responses.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}


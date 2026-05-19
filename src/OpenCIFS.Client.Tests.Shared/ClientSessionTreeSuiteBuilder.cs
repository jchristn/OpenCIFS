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
    internal static class ClientSessionTreeSuiteBuilder
    {
        /// <summary>
        /// Build the client session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.SessionTree",
                displayName: "Client session and tree handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.SessionTree",
                        caseId: "ClientBuildsSessionRequestsAndTracksTreeLifecycle",
                        displayName: "Client builds session requests, authenticates, and tracks tree lifecycle state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            Smb2SessionSetupRequest initialRequest = session.CreateSessionSetupRequest(credential);
                            SpnegoNegTokenInit initialToken = SpnegoTokenCodec.DecodeNegTokenInit(initialRequest.SecurityBuffer);
                            NtlmNegotiateMessage initialMechanismToken = NtlmNegotiateMessage.ReadFrom(initialToken.MechanismToken!);

                            TestAssertions.True((initialMechanismToken.Flags & NtlmNegotiateFlags.Unicode) != 0, "Expected the initial session-setup request to negotiate Unicode NTLM messages.");
                            TestAssertions.True((initialMechanismToken.Flags & NtlmNegotiateFlags.ExtendedSessionSecurity) != 0, "Expected the initial session-setup request to negotiate NTLM extended session security.");
                            TestAssertions.Equal("WORKGROUP", initialMechanismToken.DomainName, "Expected the initial NTLM negotiate message to carry the user domain.");

                            Smb2SessionSetupResponse challengeResponse = CreateChallengeResponse("LAB-SERVER", "WORKGROUP", Hex("0123456789ABCDEF"));
                            Smb2SessionSetupRequest authenticateRequest = session.CreateSessionAuthenticateRequest(
                                credential,
                                sessionId: 9,
                                status: NtStatus.MoreProcessingRequired,
                                challengeResponse: challengeResponse);
                            SpnegoNegTokenResp authenticateToken = SpnegoTokenCodec.DecodeNegTokenResp(authenticateRequest.SecurityBuffer);
                            NtlmAuthenticateMessage authenticateMechanismToken = NtlmAuthenticateMessage.ReadFrom(authenticateToken.ResponseToken!);

                            TestAssertions.Equal("alice", authenticateMechanismToken.UserName, "Expected the authenticate request to carry the user name.");
                            TestAssertions.Equal("WORKGROUP", authenticateMechanismToken.DomainName, "Expected the authenticate request to carry the user domain.");
                            TestAssertions.True(authenticateMechanismToken.NtChallengeResponse.Length > 0, "Expected the authenticate request to carry an NTLMv2 challenge response.");
                            TestAssertions.True(session.SessionId == 9, "Expected the client to retain the challenged session identifier.");

                            session.ApplySessionSetupResult(
                                sessionId: 9,
                                status: NtStatus.Success,
                                response: CreateSessionSetupSuccessResponse());

                            TestAssertions.True(session.IsAuthenticated, "Expected the client to mark the session as authenticated.");
                            TestAssertions.True(session.SessionId == 9, "Expected the client to keep the authenticated session identifier.");

                            Smb2TreeConnectRequest treeConnectRequest = session.CreateTreeConnectRequest("public");
                            TestAssertions.Equal("\\\\LAB-SERVER\\public", treeConnectRequest.Path, "Expected the tree-connect path to target the configured server and share.");

                            session.ApplyTreeConnectResult(
                                shareName: "public",
                                treeId: 42,
                                status: NtStatus.Success,
                                response: new Smb2TreeConnectResponse
                                {
                                    ShareType = Smb2ShareType.Disk,
                                    ShareFlags = 0,
                                    Capabilities = 0,
                                    MaximalAccess = 0x001F01FF
                                });

                            TestAssertions.Equal(1, session.ConnectedTreeIds.Length, "Expected a single connected tree.");
                            TestAssertions.Equal(42U, session.ConnectedTreeIds[0], "Expected the client to record the server tree identifier.");

                            Smb2TreeDisconnectRequest treeDisconnectRequest = session.CreateTreeDisconnectRequest(42);
                            Smb2TreeDisconnectRequestValidator.Validate(treeDisconnectRequest);
                            session.ApplyTreeDisconnectResult(42, NtStatus.Success, new Smb2TreeDisconnectResponse());
                            TestAssertions.Equal(0, session.ConnectedTreeIds.Length, "Expected tree disconnect to clear the connected tree.");

                            Smb2LogoffRequest logoffRequest = session.CreateLogoffRequest();
                            Smb2LogoffRequestValidator.Validate(logoffRequest);
                            session.ApplyLogoffResult(NtStatus.Success, new Smb2LogoffResponse());
                            TestAssertions.False(session.IsAuthenticated, "Expected logoff to clear authentication state.");
                            TestAssertions.True(session.SessionId == null, "Expected logoff to clear the session identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.SessionTree",
                        caseId: "ClientEncryptsOutboundSmb302PacketsAndDecryptsInboundResponsesWhenSessionRequiresEncryption",
                        displayName: "Client encrypts outbound SMB 3.0.2 packets and decrypts inbound responses when the authenticated session requires encryption",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                ServerName = "LAB-SERVER",
                                MaximumDialect = SmbDialect.Smb302,
                                PreferEncryption = true
                            });
                            OpenCifsClientCredential credential = CreateCredential();
                            session.CreateNegotiateRequest();
                            session.ApplyNegotiateResponse(new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb302,
                                ServerGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f"),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 65536,
                                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302),
                                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302)
                            });

                            Smb2SessionSetupRequest initialRequest = session.CreateSessionSetupRequest(credential);
                            _ = initialRequest;
                            byte[] serverChallenge = Hex("0123456789ABCDEF");
                            Smb2SessionSetupResponse challengeResponse = CreateChallengeResponse("LAB-SERVER", "WORKGROUP", serverChallenge);
                            Smb2SessionSetupRequest authenticateRequest = session.CreateSessionAuthenticateRequest(
                                credential,
                                sessionId: 9,
                                status: NtStatus.MoreProcessingRequired,
                                challengeResponse: challengeResponse);
                            SpnegoNegTokenResp authenticateToken = SpnegoTokenCodec.DecodeNegTokenResp(authenticateRequest.SecurityBuffer);
                            NtlmAuthenticateMessage authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateToken.ResponseToken!);
                            TestAssertions.True(
                                NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                    password: credential.Password,
                                    userName: credential.UserName,
                                    userDomain: credential.UserDomain,
                                    serverChallenge: serverChallenge,
                                    ntChallengeResponse: authenticateMessage.NtChallengeResponse,
                                    lmChallengeResponse: authenticateMessage.LmChallengeResponse,
                                    verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet),
                                "Expected the client NTLM authenticate request to remain verifiable for the SMB3 encryption test.");
                            TestAssertions.True(verifiedResponseSet != null, "Expected the verified NTLM response set for the SMB3 encryption test.");

                            session.ApplySessionSetupResult(
                                sessionId: 9,
                                status: NtStatus.Success,
                                response: CreateSessionSetupSuccessResponse(Smb2SessionFlags.EncryptData));

                            TestAssertions.True(session.IsAuthenticated, "Expected the SMB3 test session to authenticate successfully.");
                            TestAssertions.True(session.IsSessionEncryptionRequired, "Expected the SMB3 test session to require encryption after session setup.");

                            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: session.SessionId!.Value);
                            TestAssertions.True((requestHeader.Flags & Smb2HeaderFlags.Signed) == 0, "Expected encrypted SMB3 requests to omit the SMB2 Signed flag.");

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(requestHeader, new Smb2EchoRequest().ToByteArray())
                            });
                            byte[] encryptedRequestBytes = session.FinalizeRequestPacket(requestPacket);
                            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedRequestBytes), "Expected the authenticated SMB3 client request to be wrapped in a transform header.");

                            SmbSessionKeySet keySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = verifiedResponseSet!.SessionBaseKey,
                                    Dialect = SmbDialect.Smb302,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Ccm
                                });

                            Smb2Header responseHeader = CreateResponseHeader(
                                requestHeader,
                                grantedCredits: 3,
                                flags: Smb2HeaderFlags.ServerToRedir);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(responseHeader, new Smb2EchoResponse().ToByteArray())
                            });
                            byte[] encryptedResponseBytes = Smb3MessageTransform.EncryptPacket(
                                responsePacket.ToByteArray(),
                                session.SessionId.Value,
                                keySet.EncryptionKey);
                            byte[] unwrappedResponseBytes = session.UnwrapResponsePacket(encryptedResponseBytes);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(unwrappedResponseBytes);

                            session.ValidateResponsePacket(parsedResponsePacket, unwrappedResponseBytes);
                            session.ApplyResponseHeader(parsedResponsePacket.Entries[0].Header);
                            Smb2EchoResponseValidator.Validate(Smb2EchoResponse.ReadFrom(parsedResponsePacket.Entries[0].Payload));
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.SessionTree",
                        caseId: "ClientRejectsTamperedEncryptedSmb302Responses",
                        displayName: "Client rejects tampered SMB 3.0.2 encrypted responses when the authenticated session requires encryption",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                ServerName = "LAB-SERVER",
                                MaximumDialect = SmbDialect.Smb302,
                                PreferEncryption = true
                            });
                            OpenCifsClientCredential credential = CreateCredential();
                            session.CreateNegotiateRequest();
                            session.ApplyNegotiateResponse(new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb302,
                                ServerGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f"),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 65536,
                                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302),
                                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302)
                            });

                            byte[] serverChallenge = Hex("0123456789ABCDEF");
                            session.CreateSessionSetupRequest(credential);
                            Smb2SessionSetupRequest authenticateRequest = session.CreateSessionAuthenticateRequest(
                                credential,
                                sessionId: 9,
                                status: NtStatus.MoreProcessingRequired,
                                challengeResponse: CreateChallengeResponse("LAB-SERVER", "WORKGROUP", serverChallenge));
                            SpnegoNegTokenResp authenticateToken = SpnegoTokenCodec.DecodeNegTokenResp(authenticateRequest.SecurityBuffer);
                            NtlmAuthenticateMessage authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateToken.ResponseToken!);
                            TestAssertions.True(
                                NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                    password: credential.Password,
                                    userName: credential.UserName,
                                    userDomain: credential.UserDomain,
                                    serverChallenge: serverChallenge,
                                    ntChallengeResponse: authenticateMessage.NtChallengeResponse,
                                    lmChallengeResponse: authenticateMessage.LmChallengeResponse,
                                    verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet),
                                "Expected the client NTLM authenticate request to remain verifiable for the SMB3 tamper test.");
                            TestAssertions.True(verifiedResponseSet != null, "Expected the verified NTLM response set for the SMB3 tamper test.");

                            session.ApplySessionSetupResult(
                                sessionId: 9,
                                status: NtStatus.Success,
                                response: CreateSessionSetupSuccessResponse(Smb2SessionFlags.EncryptData));

                            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: session.SessionId!.Value);
                            Smb2Header responseHeader = CreateResponseHeader(
                                requestHeader,
                                grantedCredits: 3,
                                flags: Smb2HeaderFlags.ServerToRedir);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(responseHeader, new Smb2EchoResponse().ToByteArray())
                            });
                            SmbSessionKeySet keySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = verifiedResponseSet!.SessionBaseKey,
                                    Dialect = SmbDialect.Smb302,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Ccm
                                });
                            byte[] encryptedResponseBytes = Smb3MessageTransform.EncryptPacket(
                                responsePacket.ToByteArray(),
                                session.SessionId.Value,
                                keySet.EncryptionKey);
                            encryptedResponseBytes[encryptedResponseBytes.Length - 1] ^= 0x01;

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.UnwrapResponsePacket(encryptedResponseBytes),
                                "Expected the client to reject tampered SMB3 encrypted response packets.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.SessionTree",
                        caseId: "ClientRejectsMisorderedOrMalformedSessionInputs",
                        displayName: "Client rejects misordered or malformed session and tree inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientCredential credential = CreateCredential();
                            OpenCifsClientSession unnegotiatedSession = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                ServerName = "LAB-SERVER"
                            });
                            TestAssertions.Throws<InvalidOperationException>(
                                () => unnegotiatedSession.CreateSessionSetupRequest(credential),
                                "Creating session setup before negotiate should fail.");

                            OpenCifsClientSession negotiatedSession = CreateNegotiatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateTreeConnectRequest("public"),
                                "Tree connect should fail before authentication completes.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateSessionAuthenticateRequest(
                                    credential,
                                    sessionId: 1,
                                    status: NtStatus.Success,
                                    challengeResponse: CreateChallengeResponse("LAB-SERVER", "WORKGROUP", Hex("0123456789ABCDEF"))),
                                "The client should require MoreProcessingRequired before building the authenticate request.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.ApplySessionSetupResult(
                                    sessionId: 1,
                                    status: NtStatus.Success,
                                    response: CreateSessionSetupSuccessResponse()),
                                "Applying session-setup success without a derived session key should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.SessionTree",
                        caseId: "ClientExposesStatusExceptionsForServerFailures",
                        displayName: "Client session and tree apply paths expose SMB status exceptions for server failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            OpenCifsStatusException treeConnectException;

                            try
                            {
                                session.ApplyTreeConnectResult("public", 0, NtStatus.AccessDenied, new Smb2TreeConnectResponse());
                                throw new InvalidOperationException("Expected tree-connect failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                treeConnectException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.TreeConnect, treeConnectException.Command, "Expected the tree-connect failure to report the TreeConnect command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, treeConnectException.Status, "Expected the tree-connect failure to report STATUS_ACCESS_DENIED.");
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, treeConnectException.Category, "Expected the tree-connect failure to normalize to AccessDenied.");

                            OpenCifsStatusException sessionSetupException;

                            try
                            {
                                session.ApplySessionSetupResult(9, NtStatus.AccessDenied, new Smb2SessionSetupResponse());
                                throw new InvalidOperationException("Expected session-setup failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                sessionSetupException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.SessionSetup, sessionSetupException.Command, "Expected the session-setup failure to report the SessionSetup command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, sessionSetupException.Status, "Expected the session-setup failure to report STATUS_ACCESS_DENIED.");
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, sessionSetupException.Category, "Expected the session-setup failure to normalize to AccessDenied.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

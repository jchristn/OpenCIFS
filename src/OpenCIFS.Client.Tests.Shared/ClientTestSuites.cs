namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
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
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;

    /// <summary>
    /// Shared Touchstone suites for client bootstrap validation.
    /// </summary>
    public static class ClientTestSuites
    {
        private const string DirectTcpPortReservationSemaphoreName = "OpenCIFS.DirectTcpTestPortReservation";
        private static readonly AsyncLocal<DirectTcpPortReservation?> _CurrentDirectTcpPortReservation = new AsyncLocal<DirectTcpPortReservation?>();

        /// <summary>
        /// All shared client test suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    ClientDefaultsSuite(),
                    ClientNegotiationSuite(),
                    ClientSessionTreeSuite(),
                    ClientEchoSuite(),
                    ClientCreditHeaderSuite(),
                    ClientChangeNotifySuite(),
                    ClientCompoundingSuite(),
                    ClientFileIoSuite(),
                    ClientLockingSuite(),
                    ClientIoctlSuite(),
                    ClientMetadataSuite(),
                    ClientOplockSuite(),
                    ClientLeaseSuite(),
                    ClientConnectionSuite(),
                    ClientFacadeSuite()
                };
            }
        }

        /// <summary>
        /// Build the client defaults suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientDefaultsSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Defaults",
                displayName: "Client bootstrap defaults",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "DefaultConnectionSettings",
                        displayName: "Client defaults target modern signed sessions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientOptions options = new OpenCifsClientOptions();

                            if (!StringComparer.Ordinal.Equals(options.ServerName, "127.0.0.1"))
                            {
                                throw new InvalidOperationException("Expected default server name 127.0.0.1.");
                            }

                            if (options.ServerPort != 445)
                            {
                                throw new InvalidOperationException("Expected default server port 445.");
                            }

                            if (options.ConnectTimeoutMs != 30000)
                            {
                                throw new InvalidOperationException("Expected default timeout 30000ms.");
                            }

                            if (!options.RequireSigning)
                            {
                                throw new InvalidOperationException("Signing should be required by default.");
                            }

                            if (!options.PreferEncryption)
                            {
                                throw new InvalidOperationException("Encryption should be preferred by default.");
                            }

                            options.Validate();
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "InvalidDialectRangeRejected",
                        displayName: "Client options reject an invalid dialect range",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientOptions options = new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb311,
                                MaximumDialect = SmbDialect.Smb2002
                            };

                            try
                            {
                                options.Validate();
                            }
                            catch (ArgumentException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected Validate to reject a reversed dialect range.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "ClientSuitesExposePositiveAndNegativeVariants",
                        displayName: "Client shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(All, "Client");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientNegotiationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Negotiate",
                displayName: "Client negotiate handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAdvertisesImplementedDialects",
                        displayName: "Client negotiate request advertises the implemented SMB 2.0.2 and SMB 2.1 dialects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest request = session.CreateNegotiateRequest();

                            if (request.Dialects.Length != 2)
                            {
                                throw new InvalidOperationException("Expected exactly two currently implemented client dialects.");
                            }

                            if (request.Dialects[0] != SmbDialect.Smb2002 || request.Dialects[1] != SmbDialect.Smb21)
                            {
                                throw new InvalidOperationException("Expected SMB 2.0.2 and SMB 2.1 to be the currently implemented client dialects.");
                            }

                            if (request.ClientGuid != session.ClientGuid)
                            {
                                throw new InvalidOperationException("Expected the negotiate request to carry the session client GUID.");
                            }

                            if ((request.SecurityMode & Smb2SecurityMode.SigningRequired) == 0)
                            {
                                throw new InvalidOperationException("Expected the default client request to require signing.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAppliesCompatibleNegotiationResponse",
                        displayName: "Client negotiate handling accepts a compatible server response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions());
                            session.CreateNegotiateRequest();
                            Guid serverGuid = Guid.NewGuid();
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb21,
                                ServerGuid = serverGuid,
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536
                            };

                            session.ApplyNegotiateResponse(response);

                            if (!session.IsNegotiated)
                            {
                                throw new InvalidOperationException("Expected the client session to become negotiated.");
                            }

                            if (session.NegotiatedDialect != SmbDialect.Smb21)
                            {
                                throw new InvalidOperationException("Expected the client session to negotiate SMB 2.1.");
                            }

                            if (session.ServerGuid != serverGuid)
                            {
                                throw new InvalidOperationException("Expected the client session to record the negotiated server GUID.");
                            }

                            if (!session.IsSigningRequired)
                            {
                                throw new InvalidOperationException("Expected signing to remain required after negotiation.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientRejectsUnexpectedNegotiationDialect",
                        displayName: "Client negotiate handling rejects a server response that selects an unoffered dialect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions());
                            session.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb30,
                                ServerGuid = Guid.NewGuid(),
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536
                            };

                            try
                            {
                                session.ApplyNegotiateResponse(response);
                            }
                            catch (InvalidOperationException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected the client session to reject an unoffered dialect.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientClampsAdvertisedDialectsToConfiguredMaximum",
                        displayName: "Client negotiate request clamps the advertised dialect list to a configured SMB 2.0.2 maximum",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            Smb2NegotiateRequest request = session.CreateNegotiateRequest();

                            TestAssertions.Equal(1, request.Dialects.Length, "Expected the client dialect list to clamp to SMB 2.0.2.");
                            TestAssertions.Equal(SmbDialect.Smb2002, request.Dialects[0], "Expected the configured maximum dialect to clamp the client negotiate request.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientSessionTreeSuite()
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
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientCreditHeaderSuite()
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
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => missingFlagSession.ApplyResponseHeader(CreateResponseHeader(missingFlagRequest, flags: Smb2HeaderFlags.None)),
                                "Expected the client to reject response headers without the ServerToRedir flag.");

                            OpenCifsClientSession unknownMessageSession = CreateNegotiatedClient();
                            unknownMessageSession.CreateRequestHeader(Smb2Command.Negotiate);
                            TestAssertions.Throws<ProtocolValidationException>(
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

                            (OpenCifsServerHost host, OpenCifsClientSession session, ulong sessionId) = CreateAuthenticatedLoopbackPair();
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
                        caseId: "ClientRejectsUnsignedOrTamperedSignedResponses",
                        displayName: "Client rejects missing or tampered SMB2 signatures on authenticated echo responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            {
                                (OpenCifsServerHost host, OpenCifsClientSession session, ulong sessionId) = CreateAuthenticatedLoopbackPair();
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

                                TestAssertions.Throws<ProtocolValidationException>(
                                    () => session.ValidateResponsePacket(parsedUnsignedResponsePacket, unsignedResponseBytes),
                                    "Expected the client to reject authenticated echo responses that omit the required SMB2 Signed flag.");
                            }

                            {
                                (OpenCifsServerHost host, OpenCifsClientSession session, ulong sessionId) = CreateAuthenticatedLoopbackPair();
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

                                TestAssertions.Throws<ProtocolValidationException>(
                                    () => session.ValidateResponsePacket(parsedTamperedResponsePacket, tamperedResponseBytes),
                                    "Expected the client to reject authenticated echo responses whose SMB2 signature no longer verifies.");
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client SMB2 CHANGE_NOTIFY suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientChangeNotifySuite()
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

                            TestAssertions.Throws<ProtocolValidationException>(
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

                            TestAssertions.Throws<ProtocolValidationException>(
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

        /// <summary>
        /// Build the client echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientEchoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Echo",
                displayName: "Client echo handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Echo",
                        caseId: "ClientBuildsEchoRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds authenticated echo requests and accepts successful responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            session.ApplyEchoResult(NtStatus.Success, new Smb2EchoResponse());

                            TestAssertions.True(session.IsAuthenticated, "Expected echo handling to preserve authenticated client state.");
                            TestAssertions.True(session.SessionId == 9, "Expected echo handling to preserve the authenticated session identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Echo",
                        caseId: "ClientRejectsEchoBeforeAuthenticationOrOnFailureStatus",
                        displayName: "Client rejects echo use before authentication and rejects failed echo results",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession unauthenticatedSession = CreateNegotiatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => unauthenticatedSession.CreateEchoRequest(),
                                "An authenticated session should be required before building SMB2 echo requests.");

                            OpenCifsClientSession authenticatedSession = CreateAuthenticatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => authenticatedSession.ApplyEchoResult(NtStatus.AccessDenied, new Smb2EchoResponse()),
                                "A failed SMB2 echo response should be rejected by the client.");
                            TestAssertions.Throws<ArgumentNullException>(
                                () => authenticatedSession.ApplyEchoResult(NtStatus.Success, null!),
                                "A null SMB2 echo response should be rejected by the client.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client SMB2 compounding suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientCompoundingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Compounding",
                displayName: "Client SMB2 compounding handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientAppliesCompoundedResponsePacketHeaders",
                        displayName: "Client applies compounded response headers in wire order and releases pending requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            GrantCredits(session, 4);

                            Smb2Header firstPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2Header secondPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(firstPendingHeader), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(secondPendingHeader), Array.Empty<byte>())
                                });

                            session.ApplyCompoundResponsePacket(responsePacket);

                            TestAssertions.True(responsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response header to point at the next entry.");
                            TestAssertions.Equal(4, session.AvailableCredits, "Expected compounded response headers to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected compounded response headers to complete every pending request in the packet.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientRejectsUnknownMessageInCompoundedResponsePacket",
                        displayName: "Client rejects a compounded response packet that includes an unknown SMB2 message identifier",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            GrantCredits(session, 4);

                            Smb2Header knownPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(knownPendingHeader), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(
                                        new Smb2Header
                                        {
                                            CreditCharge = 0,
                                            Status = NtStatus.Success,
                                            Command = Smb2Command.SessionSetup,
                                            CreditRequest = 1,
                                            Flags = Smb2HeaderFlags.ServerToRedir,
                                            NextCommand = 0,
                                            MessageId = 99,
                                            Signature = new byte[16]
                                        },
                                        Array.Empty<byte>())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.ApplyCompoundResponsePacket(responsePacket),
                                "Expected the client to reject compounded response headers that do not match a pending SMB2 message identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientBuildsRelatedCompoundHeadersAndAcceptsRelatedResponses",
                        displayName: "Client builds related compounded request headers and accepts related response headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            GrantCredits(session, 3);

                            Smb2Header createHeader = session.CreateRequestHeader(Smb2Command.Create, treeId: 42, sessionId: session.SessionId!.Value);
                            Smb2Header closeHeader = session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: session.SessionId.Value);
                            TestAssertions.Equal(Smb2HeaderFlags.RelatedOperations, closeHeader.Flags, "Expected the client to mark related compounded requests explicitly.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(createHeader, flags: Smb2HeaderFlags.ServerToRedir), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(closeHeader, flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations), Array.Empty<byte>())
                                });

                            session.ApplyCompoundResponsePacket(responsePacket);
                            TestAssertions.Equal(3, session.AvailableCredits, "Expected related compounded response headers to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected related compounded response headers to complete every pending request.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client file-I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientFileIoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.FileIo",
                displayName: "Client file-I/O handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientBuildsFileIoRequestsAndTracksOpenLifecycle",
                        displayName: "Client builds create/read/write/flush/close requests and tracks open lifecycle state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            Smb2CreateRequest createRequest = session.CreateCreateRequest(42, "folder/notes.txt");
                            TestAssertions.Equal("folder\\notes.txt", createRequest.Name, "Expected the client to normalize relative create paths.");

                            Smb2CreateRequest deleteOnCloseRequest = session.CreateCreateRequest(
                                42,
                                "folder/temp.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose);
                            TestAssertions.Equal(0xC0010000U, deleteOnCloseRequest.DesiredAccess, "Unexpected delete-on-close desired-access mask.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                deleteOnCloseRequest.CreateOptions,
                                "Unexpected delete-on-close create options.");

                            Smb2CreateRequest directoryCreateRequest = session.CreateCreateRequest(
                                42,
                                "folder/new-directory",
                                desiredAccess: 0x80000000U,
                                fileAttributes: FileAttributes.Directory,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Create,
                                createOptions: Smb2CreateOptions.DirectoryFile);
                            TestAssertions.Equal("folder\\new-directory", directoryCreateRequest.Name, "Expected the client to normalize relative directory-create paths.");
                            TestAssertions.Equal(FileAttributes.Directory, directoryCreateRequest.FileAttributes, "Unexpected directory-create file attributes.");
                            TestAssertions.Equal(Smb2CreateDisposition.Create, directoryCreateRequest.CreateDisposition, "Unexpected directory-create disposition.");
                            TestAssertions.Equal(Smb2CreateOptions.DirectoryFile, directoryCreateRequest.CreateOptions, "Unexpected directory-create options.");

                            Smb2CreateRequest directoryDeleteOnCloseRequest = session.CreateCreateRequest(
                                42,
                                "folder/transient-directory",
                                desiredAccess: 0x80010000U,
                                fileAttributes: FileAttributes.Directory,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.OpenIf,
                                createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose);
                            TestAssertions.Equal(0x80010000U, directoryDeleteOnCloseRequest.DesiredAccess, "Unexpected directory delete-on-close desired-access mask.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                directoryDeleteOnCloseRequest.CreateOptions,
                                "Unexpected directory delete-on-close create options.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "folder/notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 100,
                                    VolatileFileId = 101,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            TestAssertions.Equal(1, session.OpenCount, "Expected the client to track the newly created open.");
                            TestAssertions.Equal("folder\\notes.txt", openState.Path, "Unexpected tracked client open path.");

                            Smb2WriteRequest writeRequest = session.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x01, 0x02, 0x03 }, 0);
                            TestAssertions.SequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, writeRequest.DataBuffer, "Unexpected client write payload.");
                            uint writeCount = session.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2WriteResponse
                            {
                                Count = 3
                            });
                            TestAssertions.Equal(3U, writeCount, "Unexpected client-observed write count.");

                            Smb2FlushRequest flushRequest = session.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                            TestAssertions.Equal(101UL, flushRequest.VolatileFileId, "Unexpected client flush-request volatile file identifier.");
                            session.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2FlushResponse());

                            Smb2ReadRequest readRequest = session.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 3, 0, minimumCount: 1);
                            TestAssertions.Equal(1U, readRequest.MinimumCount, "Unexpected client read-request minimum count.");
                            byte[] readBytes = session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x01, 0x02, 0x03 },
                                DataRemaining = 0,
                                Flags = 0
                            });
                            TestAssertions.SequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, readBytes, "Unexpected client-observed read payload.");

                            Smb2CloseRequest closeRequest = session.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true);
                            TestAssertions.Equal(Smb2CloseFlags.PostQueryAttributes, closeRequest.Flags, "Unexpected client close-request flags.");
                            session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2CloseResponse
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                EndOfFile = 3,
                                FileAttributes = FileAttributes.Normal
                            });
                            TestAssertions.Equal(0, session.OpenCount, "Expected the client to drop the tracked open after close.");

                            session.ApplyCreateResult(
                                42,
                                "folder\\transient.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 200,
                                    VolatileFileId = 201,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            TestAssertions.Equal(1, session.OpenCount, "Expected the client to track a second open before tree disconnect.");

                            session.ApplyTreeDisconnectResult(42, NtStatus.Success, new Smb2TreeDisconnectResponse());
                            TestAssertions.Equal(0, session.OpenCount, "Expected tree disconnect to drop all opens on the disconnected tree.");
                            TestAssertions.Equal(0, session.ConnectedTreeIds.Length, "Expected tree disconnect to remove the connected tree.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientRejectsInvalidFileIoStateAndHandlesEof",
                        displayName: "Client rejects invalid file-I/O state transitions and reports EOF cleanly",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateCreateRequest(99, "notes.txt"),
                                "Creating a file request on an unknown tree should fail.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateReadRequest(1, 2, 4, 0),
                                "Reading from an unknown open should fail.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 300,
                                    VolatileFileId = 301,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            byte[] eofBytes = session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.EndOfFile, new Smb2ReadResponse());
                            TestAssertions.Equal(0, eofBytes.Length, "Expected EOF reads to return an empty payload.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2ReadResponse
                                {
                                    DataBuffer = Array.Empty<byte>(),
                                    DataRemaining = 0,
                                    Flags = 0
                                }),
                                "Successful read results with an empty payload should fail validation.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientBuildsSupersedeAndOverwriteCreateRequests",
                        displayName: "Client builds bounded overwrite, supersede, and create-attribute requests and rejects supersede without delete access",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            Smb2CreateRequest overwriteIfRequest = session.CreateCreateRequest(
                                42,
                                "folder/replace.txt",
                                desiredAccess: 0xC0000000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.OverwriteIf,
                                fileAttributes: FileAttributes.Hidden);
                            TestAssertions.Equal("folder\\replace.txt", overwriteIfRequest.Name, "Expected overwrite-if requests to preserve the normalized path.");
                            TestAssertions.Equal(Smb2CreateDisposition.OverwriteIf, overwriteIfRequest.CreateDisposition, "Unexpected overwrite-if create disposition.");
                            TestAssertions.Equal(FileAttributes.Hidden, overwriteIfRequest.FileAttributes, "Expected overwrite-if requests to preserve create-time file attributes.");

                            Smb2CreateRequest supersedeRequest = session.CreateCreateRequest(
                                42,
                                "folder/supersede.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Supersede);
                            TestAssertions.Equal(Smb2CreateDisposition.Supersede, supersedeRequest.CreateDisposition, "Unexpected supersede create disposition.");
                            TestAssertions.Equal(0xC0010000U, supersedeRequest.DesiredAccess, "Expected FILE_SUPERSEDE requests to preserve DELETE access.");

                            Smb2CreateRequest deleteOnCloseReadOnlyRequest = session.CreateCreateRequest(
                                42,
                                "folder/transient-readonly.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Create,
                                createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                fileAttributes: FileAttributes.ReadOnly);
                            TestAssertions.Equal(FileAttributes.ReadOnly, deleteOnCloseReadOnlyRequest.FileAttributes, "Expected delete-on-close create requests to preserve read-only file attributes.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                deleteOnCloseReadOnlyRequest.CreateOptions,
                                "Expected delete-on-close create requests to preserve the requested create options.");

                            OpenState overwrittenOpen = session.ApplyCreateResult(
                                42,
                                "folder/replace.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Overwritten,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 320,
                                    VolatileFileId = 321,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            session.ApplyCloseResult(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId, NtStatus.Success, new Smb2CloseResponse());

                            OpenState supersededOpen = session.ApplyCreateResult(
                                42,
                                "folder/supersede.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Superseded,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 322,
                                    VolatileFileId = 323,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            session.ApplyCloseResult(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId, NtStatus.Success, new Smb2CloseResponse());
                            TestAssertions.Equal(0, session.OpenCount, "Expected superseded and overwritten opens to close cleanly.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.CreateCreateRequest(
                                    42,
                                    "folder/invalid-supersede.txt",
                                    desiredAccess: 0xC0000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Supersede),
                                "FILE_SUPERSEDE should require DELETE access.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client metadata suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientMetadataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Metadata",
                displayName: "Client metadata request and state handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Metadata",
                        caseId: "ClientBuildsMetadataRequestsAndTracksRenameDeleteState",
                        displayName: "Client builds metadata and directory-enumeration requests and tracks rename and delete-pending state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "folder\\notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 400,
                                    VolatileFileId = 401,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2QueryInfoRequest queryInfoRequest = session.CreateQueryInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                FileInformationClass.NetworkOpenInformation,
                                outputBufferLength: 512);
                            TestAssertions.Equal(Smb2InfoType.File, queryInfoRequest.InfoType, "Expected query-info requests to target file information.");
                            TestAssertions.Equal(512U, queryInfoRequest.OutputBufferLength, "Unexpected query-info output-buffer length.");

                            Smb2SetInfoRequest basicInfoRequest = session.CreateSetBasicInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new FileBasicInformation
                                {
                                    CreationTime = 0x0102030405060708UL,
                                    LastAccessTime = 0x1112131415161718UL,
                                    LastWriteTime = 0x1122334455667788UL,
                                    ChangeTime = 0x2122232425262728UL,
                                    FileAttributes = FileAttributes.Hidden
                                });
                            FileBasicInformation basicInfoPayload = FileBasicInformation.ReadFrom(basicInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.BasicInformation, basicInfoRequest.FileInfoClass, "Unexpected set-info basic information class.");
                            TestAssertions.Equal(0x0102030405060708UL, basicInfoPayload.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time.");
                            TestAssertions.Equal(0x1112131415161718UL, basicInfoPayload.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time.");
                            TestAssertions.Equal(0x1122334455667788UL, basicInfoPayload.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time.");
                            TestAssertions.Equal(0x2122232425262728UL, basicInfoPayload.ChangeTime, "Unexpected FILE_BASIC_INFORMATION change time.");
                            TestAssertions.Equal(FileAttributes.Hidden, basicInfoPayload.FileAttributes, "Unexpected FILE_BASIC_INFORMATION attributes.");

                            Smb2SetInfoRequest stickyBasicInfoRequest = session.CreateSetBasicInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new FileBasicInformation
                                {
                                    CreationTime = UInt64.MaxValue,
                                    LastAccessTime = UInt64.MaxValue,
                                    LastWriteTime = UInt64.MaxValue - 1,
                                    ChangeTime = UInt64.MaxValue,
                                    FileAttributes = FileAttributes.Hidden
                                });
                            FileBasicInformation stickyBasicInfoPayload = FileBasicInformation.ReadFrom(stickyBasicInfoRequest.Buffer);
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.CreationTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky creation-time directives.");
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.LastAccessTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky last-access directives.");
                            TestAssertions.Equal(UInt64.MaxValue - 1, stickyBasicInfoPayload.LastWriteTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky last-write directives.");
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.ChangeTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky change-time directives.");

                            Smb2SetInfoRequest allocationInfoRequest = session.CreateSetAllocationInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 32768);
                            FileAllocationInformation allocationInfoPayload = FileAllocationInformation.ReadFrom(allocationInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.AllocationInformation, allocationInfoRequest.FileInfoClass, "Unexpected set-info allocation information class.");
                            TestAssertions.Equal(32768UL, allocationInfoPayload.AllocationSize, "Unexpected FILE_ALLOCATION_INFORMATION allocation size.");

                            Smb2SetInfoRequest endOfFileInfoRequest = session.CreateSetEndOfFileInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 2048);
                            FileEndOfFileInformation endOfFileInfoPayload = FileEndOfFileInformation.ReadFrom(endOfFileInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.EndOfFileInformation, endOfFileInfoRequest.FileInfoClass, "Unexpected set-info EOF information class.");
                            TestAssertions.Equal(2048UL, endOfFileInfoPayload.EndOfFile, "Unexpected FILE_END_OF_FILE_INFORMATION EOF size.");

                            Smb2SetInfoRequest renameInfoRequest = session.CreateSetRenameInfoRequest(openState.PersistentFileId, openState.VolatileFileId, "archive/notes-renamed.txt", replaceIfExists: true);
                            FileRenameInformationType2 renameInfoPayload = FileRenameInformationType2.ReadFrom(renameInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.RenameInformation, renameInfoRequest.FileInfoClass, "Unexpected set-info rename information class.");
                            TestAssertions.True(renameInfoPayload.ReplaceIfExists, "Expected FILE_RENAME_INFORMATION_TYPE_2 to preserve ReplaceIfExists.");
                            TestAssertions.Equal("archive\\notes-renamed.txt", renameInfoPayload.FileName, "Expected rename paths to be normalized.");

                            Smb2CreateRequest directoryCreateRequest = session.CreateCreateRequest(
                                42,
                                "folder",
                                desiredAccess: 0x80000000U,
                                createDisposition: Smb2CreateDisposition.Open,
                                createOptions: Smb2CreateOptions.DirectoryFile);
                            TestAssertions.Equal(Smb2CreateOptions.DirectoryFile, directoryCreateRequest.CreateOptions, "Expected directory create requests to preserve the directory create option.");
                            TestAssertions.Equal("folder", directoryCreateRequest.Name, "Expected directory create requests to preserve the normalized path.");

                            OpenState directoryOpenState = session.ApplyCreateResult(
                                42,
                                "folder",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Directory,
                                    PersistentFileId = 410,
                                    VolatileFileId = 411,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2QueryDirectoryRequest queryDirectoryRequest = session.CreateQueryDirectoryRequest(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                FileInformationClass.DirectoryInformation,
                                outputBufferLength: 256,
                                fileNamePattern: "*.txt",
                                flags: Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry);
                            TestAssertions.Equal(FileInformationClass.DirectoryInformation, queryDirectoryRequest.FileInfoClass, "Unexpected query-directory information class.");
                            TestAssertions.Equal("*.txt", queryDirectoryRequest.FileNamePattern, "Unexpected query-directory search pattern.");
                            TestAssertions.Equal(
                                Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                queryDirectoryRequest.Flags,
                                "Unexpected query-directory flags.");

                            byte[] queryDirectoryBytes = session.ApplyQueryDirectoryResult(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2QueryDirectoryResponse
                                {
                                    OutputBuffer = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                                    {
                                        new FileDirectoryInformationEntry
                                        {
                                            FileName = "notes.txt",
                                            EndOfFile = 17,
                                            AllocationSize = 32,
                                            FileAttributes = FileAttributes.Archive
                                        }
                                    })
                                });
                            FileDirectoryInformationEntry[] queryDirectoryEntries = FileDirectoryInformationEntry.DecodeEntries(queryDirectoryBytes);
                            TestAssertions.Equal(1, queryDirectoryEntries.Length, "Expected a single client-observed directory entry.");
                            TestAssertions.Equal("notes.txt", queryDirectoryEntries[0].FileName, "Unexpected client-observed directory entry name.");

                            byte[] exhaustedDirectoryBytes = session.ApplyQueryDirectoryResult(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                NtStatus.NoMoreFiles,
                                new Smb2QueryDirectoryResponse());
                            TestAssertions.Equal(0, exhaustedDirectoryBytes.Length, "Expected exhausted query-directory results to return an empty payload.");

                            Smb2SetInfoRequest directoryRenameInfoRequest = session.CreateSetRenameInfoRequest(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                "archive/folder-renamed");
                            FileRenameInformationType2 directoryRenameInfoPayload = FileRenameInformationType2.ReadFrom(directoryRenameInfoRequest.Buffer);
                            TestAssertions.Equal("archive\\folder-renamed", directoryRenameInfoPayload.FileName, "Expected directory rename paths to be normalized.");

                            byte[] queryResultBytes = session.ApplyQueryInfoResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2QueryInfoResponse
                                {
                                    OutputBuffer = new FileNetworkOpenInformation
                                    {
                                        AllocationSize = 2048,
                                        EndOfFile = 17,
                                        FileAttributes = FileAttributes.Archive
                                    }.ToByteArray()
                                });
                            FileNetworkOpenInformation queryResult = FileNetworkOpenInformation.ReadFrom(queryResultBytes);
                            TestAssertions.Equal(2048UL, queryResult.AllocationSize, "Unexpected client-observed FILE_NETWORK_OPEN_INFORMATION allocation size.");
                            TestAssertions.Equal(17UL, queryResult.EndOfFile, "Unexpected client-observed FILE_NETWORK_OPEN_INFORMATION EOF size.");

                            session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), deletePending: true);
                            TestAssertions.True(openState.IsDeletePending, "Expected successful disposition updates to mark the tracked open as delete-pending.");

                            session.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), "archive/notes-renamed.txt");
                            TestAssertions.Equal("archive\\notes-renamed.txt", openState.Path, "Expected successful rename updates to normalize the tracked open path.");

                            session.ApplySetRenameInfoResult(directoryOpenState.PersistentFileId, directoryOpenState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), "archive/folder-renamed");
                            TestAssertions.Equal("archive\\folder-renamed", directoryOpenState.Path, "Expected successful directory rename updates to normalize the tracked directory-open path.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Metadata",
                        caseId: "ClientRejectsMetadataRequestsForUnknownOpenOrFailedStatus",
                        displayName: "Client rejects metadata requests for unknown opens and preserves state on failed responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateQueryInfoRequest(1, 2, FileInformationClass.BasicInformation),
                                "Query-info requests should fail for an unknown open.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateSetAllocationInfoRequest(1, 2, 128),
                                "Set-info requests should fail for an unknown open.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateQueryDirectoryRequest(1, 2, FileInformationClass.DirectoryInformation),
                                "Query-directory requests should fail for an unknown open.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 500,
                                    VolatileFileId = 501,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryInfoResponse()),
                                "Failed query-info results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), deletePending: true),
                                "Failed set-info disposition results should throw.");
                            TestAssertions.False(openState.IsDeletePending, "Failed set-info disposition results should not mutate tracked delete-pending state.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryDirectoryResponse()),
                                "Failed query-directory results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), "archive\\blocked.txt"),
                                "Failed set-info rename results should throw.");
                            TestAssertions.Equal("notes.txt", openState.Path, "Failed set-info rename results should not mutate the tracked path.");

                            OpenCifsStatusException queryInfoException;

                            try
                            {
                                session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryInfoResponse());
                                throw new InvalidOperationException("Expected query-info failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                queryInfoException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.QueryInfo, queryInfoException.Command, "Expected query-info failure to report the QueryInfo command.");
                            TestAssertions.Equal(NtStatus.BufferTooSmall, queryInfoException.Status, "Expected query-info failure to report STATUS_BUFFER_TOO_SMALL.");

                            OpenCifsStatusException setInfoException;

                            try
                            {
                                session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), deletePending: true);
                                throw new InvalidOperationException("Expected set-info failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                setInfoException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.SetInfo, setInfoException.Command, "Expected set-info failure to report the SetInfo command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, setInfoException.Status, "Expected set-info failure to report STATUS_ACCESS_DENIED.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client oplock suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Oplock",
                displayName: "Client oplock-break handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Oplock",
                        caseId: "ClientAppliesSignedOplockBreakNotificationsAndAcknowledgesExclusiveBreaks",
                        displayName: "Client applies signed oplock-break notifications and acknowledges exclusive breaks",
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
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.Signed,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 42,
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

                            (OpenState appliedOpenState, Smb2OplockLevel previousOplockLevel, Smb2OplockLevel newOplockLevel, bool requiresAcknowledgment) =
                                session.ApplyOplockBreakNotification(42, notification);
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
                        caseId: "ClientRejectsUnexpectedOrUnsignedOplockBreakNotifications",
                        displayName: "Client rejects unexpected or unsigned oplock-break notifications",
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

                            Smb2Header unsignedHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Success,
                                Command = Smb2Command.OplockBreak,
                                CreditRequest = 0,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 42,
                                AsyncId = 0,
                                SessionId = session.SessionId!.Value,
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
                                new Smb2CompoundPacketEntry(unsignedHeader, unsignedNotification.ToByteArray())
                            }).ToByteArray();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.ValidateOplockBreakNotificationPacket(Smb2CompoundPacket.ReadFrom(unsignedPacketBytes), unsignedPacketBytes),
                                "Expected signed sessions to reject unsigned oplock-break notifications.");

                            TestAssertions.Throws<ProtocolValidationException>(
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

        /// <summary>
        /// Build the client lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Lease",
                displayName: "Client SMB 2.1 lease handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Lease",
                        caseId: "ClientAppliesSignedLeaseBreakNotificationsAndAcknowledgesThem",
                        displayName: "Client applies signed lease-break notifications and acknowledges them",
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
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.Signed,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 42,
                                AsyncId = 0,
                                SessionId = session.SessionId!.Value,
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

                            (OpenState appliedOpenState, Smb2LeaseState previousLeaseState, Smb2LeaseState newLeaseState, bool requiresAcknowledgment) =
                                session.ApplyLeaseBreakNotification(42, notification);
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
                        caseId: "ClientRejectsUnexpectedOrUnsignedLeaseBreakNotifications",
                        displayName: "Client rejects unexpected or unsigned lease-break notifications",
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

                            Smb2Header unsignedHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Success,
                                Command = Smb2Command.OplockBreak,
                                CreditRequest = 0,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                NextCommand = 0,
                                MessageId = UInt64.MaxValue,
                                ProcessId = 0,
                                TreeId = 42,
                                AsyncId = 0,
                                SessionId = session.SessionId!.Value,
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
                                new Smb2CompoundPacketEntry(unsignedHeader, unsignedNotification.ToByteArray())
                            }).ToByteArray();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => session.ValidateLeaseBreakNotificationPacket(Smb2CompoundPacket.ReadFrom(unsignedPacketBytes), unsignedPacketBytes),
                                "Expected signed sessions to reject unsigned lease-break notifications.");

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

                            TestAssertions.Throws<ProtocolValidationException>(
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
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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

        /// <summary>
        /// Build the managed direct-TCP client connection suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientConnectionSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Connection",
                displayName: "Client direct-TCP connection handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionAndSessionSurfacesDoNotExposePreviewMarkers",
                        displayName: "Client connection and session surfaces do not expose preview markers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsPreviewAttribute? connectionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientConnection), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? sessionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientSession), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (connectionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the managed direct-TCP client connection surface to remain outside preview-only markers.");
                            }

                            if (sessionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the low-level client session surface to remain outside preview-only markers.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionConnectsOverDirectTcpAndHandlesLowLevelOperations",
                        displayName: "Client connection connects over direct TCP and handles authenticated tree, open, read, write, query, set, rename, enumerate, delete, and close operations",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await client.ConnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(client.IsConnected, "Expected the client connection to own an active direct-TCP transport after connect.");
                                TestAssertions.True(client.Session.IsNegotiated, "Expected connect to complete SMB2 negotiation.");

                                await client.AuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(client.IsAuthenticated, "Expected authenticate to complete the SMB2 session setup flow.");

                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.Equal("public", treeHandle.ShareName, "Unexpected connected share name.");

                                OpenCifsClientOpenHandle directoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(directoryHandle.IsClosed, "Expected directory close to retire the tracked open handle.");

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("connection-surface-data");
                                uint writtenCount = await client.WriteAsync(fileHandle, expectedBytes, 0, token).ConfigureAwait(false);
                                TestAssertions.Equal((uint)expectedBytes.Length, writtenCount, "Expected the low-level connection to acknowledge the full write length.");
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);

                                byte[] actualBytes = await client.ReadAsync(fileHandle, (uint)expectedBytes.Length, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the low-level connection to round-trip the file payload.");

                                FileNetworkOpenInformation metadataBeforeResize = FileNetworkOpenInformation.ReadFrom(await client.QueryInfoAsync(
                                    fileHandle,
                                    FileInformationClass.NetworkOpenInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.Equal((ulong)expectedBytes.Length, metadataBeforeResize.EndOfFile, "Unexpected low-level EOF size before resize.");

                                await client.SetEndOfFileAsync(fileHandle, 6, token).ConfigureAwait(false);
                                FileNetworkOpenInformation metadataAfterResize = FileNetworkOpenInformation.ReadFrom(await client.QueryInfoAsync(
                                    fileHandle,
                                    FileInformationClass.NetworkOpenInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.Equal(6UL, metadataAfterResize.EndOfFile, "Expected the low-level connection EOF mutation to update file length.");

                                await client.SetRenameAsync(fileHandle, "docs\\renamed.txt", cancellationToken: token).ConfigureAwait(false);

                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(fileHandle.IsClosed, "Expected file close to retire the tracked open handle.");

                                OpenCifsClientOpenHandle enumerationHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] enumerationBuffer = await client.QueryDirectoryAsync(
                                    enumerationHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*.txt",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] directoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the low-level connection to enumerate the created file.");
                                TestAssertions.Equal("renamed.txt", directoryEntries[0].FileName, "Unexpected low-level directory entry name after rename.");
                                TestAssertions.Equal(6UL, directoryEntries[0].EndOfFile, "Expected directory enumeration to reflect the resized EOF.");
                                await client.CloseAsync(enumerationHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle deleteFileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\renamed.txt",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.SetDeletePendingAsync(deleteFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(deleteFileHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle emptyEnumerationHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] emptyEnumerationBuffer = await client.QueryDirectoryAsync(
                                    emptyEnumerationHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] emptyDirectoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(emptyEnumerationBuffer);
                                TestAssertions.Equal(0, emptyDirectoryEntries.Length, "Expected the low-level connection to leave the directory empty after deleting the renamed file.");
                                await client.CloseAsync(emptyEnumerationHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle deleteDirectoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.SetDeletePendingAsync(deleteDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(deleteDirectoryHandle, cancellationToken: token).ConfigureAwait(false);

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.True(treeHandle.IsDisconnected, "Expected tree disconnect to retire the tracked tree handle.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "docs", "renamed.txt")), "Expected low-level delete-pending to remove the renamed file from the backing share.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected low-level delete-pending to remove the emptied directory from the backing share.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsUnauthenticatedUseBadCredentialsAndStaleHandles",
                        displayName: "Client connection rejects unauthenticated use, bad credentials, and stale handles",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            await using OpenCifsClientConnection disconnectedClient = new OpenCifsClientConnection(new OpenCifsClientOptions());
                            await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                () => disconnectedClient.AuthenticateAsync(CreateCredential(), token),
                                "Expected authenticate to reject use before connect.");
                            await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                () => disconnectedClient.TreeConnectAsync("public", token),
                                "Expected tree connect to reject use before authentication.");

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection wrongPasswordClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await wrongPasswordClient.ConnectAsync(token).ConfigureAwait(false);
                                OpenCifsClientCredential wrongCredential = new OpenCifsClientCredential
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "WrongPassword!"
                                };

                                OpenCifsStatusException authenticationException;

                                try
                                {
                                    await wrongPasswordClient.AuthenticateAsync(wrongCredential, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected the low-level connection surface to reject invalid credentials.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    authenticationException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.SessionSetup, authenticationException.Command, "Expected invalid credentials to report the SessionSetup command.");
                                TestAssertions.Equal(NtStatus.AccessDenied, authenticationException.Status, "Expected invalid credentials to report STATUS_ACCESS_DENIED.");
                                TestAssertions.False(wrongPasswordClient.IsConnected, "Expected failed authentication to tear down the direct-TCP transport.");

                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle nonEmptyDirectoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetDeletePendingAsync(nonEmptyDirectoryHandle, cancellationToken: token),
                                    "Expected the low-level connection to reject delete-pending for non-empty directories.");
                                await client.CloseAsync(nonEmptyDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected a failed low-level non-empty directory delete to preserve the child file.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected a failed low-level non-empty directory delete to preserve the directory.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.ReadAsync(fileHandle, 1, 0, cancellationToken: token),
                                    "Expected closed open handles to be rejected.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.OpenAsync(treeHandle, "docs\\other.txt", cancellationToken: token),
                                    "Expected disconnected tree handles to be rejected.");
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesChangeNotifyOverDirectTcp",
                        displayName: "Client connection completes CHANGE_NOTIFY over direct TCP for nested watched-tree file creation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                notifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: true,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle childFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\nested\\child.txt",
                                    createDisposition: Smb2CreateDisposition.Create,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(childFileHandle, cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] entries = await notifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, entries.Length, "Expected CHANGE_NOTIFY to complete with a single nested file-create entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected nested file creation to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("nested\\child.txt", entries[0].FileName, "Expected watched-tree CHANGE_NOTIFY to return a nested relative path.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterNotify = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterNotify.Length, "Expected the watched directory to contain the nested directory after CHANGE_NOTIFY completion.");
                                TestAssertions.Equal("nested", entriesAfterNotify[0].FileName, "Unexpected watched-directory entry after CHANGE_NOTIFY completion.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesRenameAndDeleteChangeNotifyOverDirectTcp",
                        displayName: "Client connection completes CHANGE_NOTIFY over direct TCP for same-directory rename and delete",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle actorFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource renameNotifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                renameNotifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> renameNotifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: renameNotifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetRenameAsync(actorFileHandle, "watched\\renamed.txt", cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] renameEntries = await renameNotifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(2, renameEntries.Length, "Expected same-directory rename CHANGE_NOTIFY to return old and new name entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename entry to keep the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename entry to keep the renamed relative file name.");

                                using CancellationTokenSource deleteNotifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                deleteNotifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<FileNotifyInformation[]> deleteNotifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: deleteNotifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetDeletePendingAsync(actorFileHandle, deletePending: true, cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(actorFileHandle, cancellationToken: token).ConfigureAwait(false);

                                FileNotifyInformation[] deleteEntries = await deleteNotifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected delete CHANGE_NOTIFY to return a single remove entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected delete CHANGE_NOTIFY to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected delete CHANGE_NOTIFY to retain the renamed relative file name.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCancelsChangeNotifyForNonMatchingEventsOverDirectTcp",
                        displayName: "Client connection keeps CHANGE_NOTIFY pending for non-matching events and cancels it over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle actorFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\sample.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.SetEndOfFileAsync(actorFileHandle, 2, token).ConfigureAwait(false);
                                await actorClient.CloseAsync(actorFileHandle, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a size-only mutation to leave a filename-only CHANGE_NOTIFY request pending.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterCancel = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterCancel.Length, "Expected the watched directory to remain queryable after cancelling CHANGE_NOTIFY.");
                                TestAssertions.Equal("sample.txt", entriesAfterCancel[0].FileName, "Unexpected watched-directory entry after cancelling CHANGE_NOTIFY.");
                                TestAssertions.Equal(2UL, entriesAfterCancel[0].EndOfFile, "Expected the non-matching size mutation to persist after cancelling CHANGE_NOTIFY.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCancelsNonRecursiveChangeNotifyForNestedCreateOverDirectTcp",
                        displayName: "Client connection keeps non-recursive CHANGE_NOTIFY pending for nested creates and cancels it over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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
                                OpenCifsClientOpenHandle watchedDirectoryHandle = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<FileNotifyInformation[]> notifyTask = watcherClient.ChangeNotifyAsync(
                                    watchedDirectoryHandle,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle childFileHandle = await actorClient.OpenAsync(
                                    actorTree,
                                    "watched\\nested\\child.txt",
                                    createDisposition: Smb2CreateDisposition.Create,
                                    cancellationToken: token).ConfigureAwait(false);
                                await actorClient.CloseAsync(childFileHandle, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a non-recursive CHANGE_NOTIFY request to remain pending for nested creates.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending non-recursive CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                byte[] enumerationBuffer = await watcherClient.QueryDirectoryAsync(
                                    watchedDirectoryHandle,
                                    FileInformationClass.FullDirectoryInformation,
                                    fileNamePattern: "*",
                                    cancellationToken: token).ConfigureAwait(false);
                                FileFullDirectoryInformationEntry[] entriesAfterCancel = FileFullDirectoryInformationEntry.DecodeEntries(enumerationBuffer);
                                TestAssertions.Equal(1, entriesAfterCancel.Length, "Expected the watched directory to remain queryable after cancelling the non-recursive CHANGE_NOTIFY request.");
                                TestAssertions.Equal("nested", entriesAfterCancel[0].FileName, "Unexpected watched-directory entry after cancelling the non-recursive CHANGE_NOTIFY request.");

                                await watcherClient.CloseAsync(watchedDirectoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionHonorsSharedReadAccessAcrossDirectTcpSessions",
                        displayName: "Client connection honors shared read access across direct TCP sessions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "shared.txt"), "shared-read-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle secondOpen = await secondClient.OpenAsync(
                                    secondTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                byte[] sharedBytes = await secondClient.ReadAsync(secondOpen, 64, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(System.Text.Encoding.UTF8.GetBytes("shared-read-data"), sharedBytes, "Expected the second direct-TCP client to read through a shared-read open.");

                                await secondClient.CloseAsync(secondOpen, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsConflictingShareAccessAcrossDirectTcpSessions",
                        displayName: "Client connection rejects conflicting share access across direct TCP sessions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "shared.txt"), "shared-read-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000001U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException shareAccessException;

                                try
                                {
                                    await secondClient.OpenAsync(
                                        secondTree,
                                        "docs\\shared.txt",
                                        desiredAccess: 0x40000000U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected a direct-TCP write open to be rejected when another session only shares the file for reads.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    shareAccessException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, shareAccessException.Command, "Expected the direct-TCP share-access failure to report the Create command.");
                                TestAssertions.Equal(NtStatus.SharingViolation, shareAccessException.Status, "Expected the direct-TCP share-access failure to report STATUS_SHARING_VIOLATION.");

                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionAppliesByteRangeLocksOverDirectTcp",
                        displayName: "Client connection applies byte-range locks and unlocks over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await client.WriteAsync(fileHandle, System.Text.Encoding.UTF8.GetBytes("lock-surface-data"), 0, token).ConfigureAwait(false);
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);

                                Smb2LockElement lockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                };
                                await client.LockAsync(fileHandle, new[] { lockElement }, token).ConfigureAwait(false);

                                Smb2LockElement unlockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                };
                                await client.LockAsync(fileHandle, new[] { unlockElement }, token).ConfigureAwait(false);
                                await client.CloseAsync(fileHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
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
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsConflictingByteRangeLocksOverDirectTcp",
                        displayName: "Client connection rejects conflicting byte-range locks over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle firstFileHandle = await firstClient.OpenAsync(
                                    firstTree,
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                await firstClient.WriteAsync(firstFileHandle, System.Text.Encoding.UTF8.GetBytes("lock-conflict-data"), 0, token).ConfigureAwait(false);
                                await firstClient.FlushAsync(firstFileHandle, token).ConfigureAwait(false);

                                Smb2LockElement exclusiveLockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                };
                                await firstClient.LockAsync(firstFileHandle, new[] { exclusiveLockElement }, token).ConfigureAwait(false);

                                OpenCifsClientOpenHandle secondFileHandle = await secondClient.OpenAsync(
                                    secondTree,
                                    "docs\\locked.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException lockException;

                                try
                                {
                                    await secondClient.LockAsync(secondFileHandle, new[] { exclusiveLockElement }, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected a conflicting byte-range lock to be rejected across direct-TCP sessions.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    lockException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Lock, lockException.Command, "Expected the conflicting byte-range lock to report the Lock command.");
                                TestAssertions.Equal(NtStatus.LockNotGranted, lockException.Status, "Expected the conflicting byte-range lock to report STATUS_LOCK_NOT_GRANTED.");

                                Smb2LockElement unlockElement = new Smb2LockElement
                                {
                                    Offset = 0,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                };
                                await firstClient.LockAsync(firstFileHandle, new[] { unlockElement }, token).ConfigureAwait(false);
                                await secondClient.CloseAsync(secondFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstFileHandle, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsNonEmptyDirectoryDeleteWithExplicitStatus",
                        displayName: "Client connection reports explicit SMB status for non-empty directory delete rejection",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "nested", "child.txt"), "child");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle directoryHandle = await client.OpenExistingPathAsync(
                                    treeHandle,
                                    "docs",
                                    desiredAccess: 0x00010000U,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException deleteException;

                                try
                                {
                                    await client.SetDeletePendingAsync(directoryHandle, true, token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected non-empty directory delete-pending to be rejected.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    deleteException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.SetInfo, deleteException.Command, "Expected non-empty directory delete rejection to report the SetInfo command.");
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, deleteException.Status, "Expected non-empty directory delete rejection to report STATUS_DIRECTORY_NOT_EMPTY.");
                                await client.CloseAsync(directoryHandle, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionReconnectsDurableBatchOpenAfterTransportDisconnect",
                        displayName: "Client connection reconnects a durable batch open after an ungraceful transport disconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-client-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle firstTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await client.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestDurableHandle: true).ConfigureAwait(false);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial direct-TCP open to be granted durable reconnect state.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the initial direct-TCP durable open to expose a reconnect token.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, durableOpen.OplockLevel, "Expected the initial durable direct-TCP open to receive a batch oplock.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                TestAssertions.False(client.IsConnected, "Expected transport simulation to tear down the active direct-TCP connection.");
                                TestAssertions.True(durableOpen.IsClosed, "Expected the original durable open handle to be retired from active use after transport loss.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the durable open handle to remain usable as a reconnect token after transport loss.");

                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await client.ReconnectDurableOpenAsync(secondTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    durableOpen.VolatileFileId == reconnectedOpen.VolatileFileId,
                                    "Expected durable reconnect to allocate a new volatile file identifier.");
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP open to remain durable.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectedOpen.OplockLevel, "Expected durable reconnect to preserve the batch oplock.");
                                TestAssertions.False(durableOpen.CanReconnectDurably, "Expected the consumed reconnect token to be retired after successful durable reconnect.");

                                byte[] actualBytes = await client.ReadAsync(reconnectedOpen, 19, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected durable reconnect to preserve file access over the new session.");

                                await client.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionPreservesDurableByteRangeLocksAcrossTransportDisconnectAndReconnect",
                        displayName: "Client connection preserves durable byte-range locks across transport disconnect and reconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-client-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection durableClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection competingClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle durableTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await durableClient.OpenAsync(
                                    durableTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestDurableHandle: true).ConfigureAwait(false);
                                await durableClient.LockAsync(
                                    durableOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await durableClient.SimulateTransportDisconnectAsync().ConfigureAwait(false);

                                await competingClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle competingTree = await competingClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle competingOpen = await competingClient.OpenAsync(
                                    competingTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException detachedReadException;

                                try
                                {
                                    await competingClient.ReadAsync(competingOpen, 4, 0, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected detached durable locks to block overlapping reads.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    detachedReadException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Read, detachedReadException.Command, "Expected detached durable lock conflicts to surface on the read command.");
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadException.Status, "Expected detached durable locks to block overlapping reads with STATUS_FILE_LOCK_CONFLICT.");

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle reconnectedTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await durableClient.ReconnectDurableOpenAsync(reconnectedTree, durableOpen, token).ConfigureAwait(false);

                                OpenCifsStatusException reconnectedLockException;

                                try
                                {
                                    await competingClient.LockAsync(
                                        competingOpen,
                                        new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        },
                                        token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected reconnected durable locks to remain enforced until the owner unlocks them.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    reconnectedLockException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Lock, reconnectedLockException.Command, "Expected the competing lock attempt to fail on the lock command.");
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockException.Status, "Expected the competing lock attempt to be rejected while the durable reconnect owner still holds the range.");

                                await durableClient.LockAsync(
                                    reconnectedOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await competingClient.LockAsync(
                                    competingOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await competingClient.CloseAsync(competingOpen, cancellationToken: token).ConfigureAwait(false);
                                await competingClient.TreeDisconnectAsync(competingTree, token).ConfigureAwait(false);
                                await durableClient.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await durableClient.TreeDisconnectAsync(reconnectedTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsDurableReconnectForNonDurableHandles",
                        displayName: "Client connection rejects durable reconnect attempts for non-durable handles",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle firstTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle ordinaryOpen = await client.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(ordinaryOpen.IsDurable, "Expected a direct-TCP open without a durable request not to be reconnectable.");
                                TestAssertions.False(ordinaryOpen.CanReconnectDurably, "Expected a non-durable direct-TCP open not to expose a reconnect token.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.ReconnectDurableOpenAsync(secondTree, ordinaryOpen, token),
                                    "Expected durable reconnect to reject non-durable open handles.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesExclusiveOplockBreakOverDirectTcp",
                        displayName: "Client connection completes exclusive oplock-break handling over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

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
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, watcherOpen.OplockLevel, "Expected the first direct-TCP open to receive an exclusive oplock grant.");

                                using CancellationTokenSource breakTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                breakTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<OpenCifsClientOplockBreakNotification> breakTask = watcherClient.WaitForOplockBreakAsync(breakTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle actorOpen = await actorClient.OpenAsync(
                                    actorTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOplockBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
                                TestAssertions.Equal("public", breakNotification.ShareName, "Expected the oplock-break notification to retain the share name.");
                                TestAssertions.Equal("shared.txt", breakNotification.Path, "Expected the oplock-break notification to retain the normalized path.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, breakNotification.PreviousOplockLevel, "Expected the oplock-break notification to report the previous exclusive oplock.");
                                TestAssertions.Equal(Smb2OplockLevel.None, breakNotification.NewOplockLevel, "Expected the oplock-break notification to lower the oplock to none.");
                                TestAssertions.True(breakNotification.WasAcknowledged, "Expected exclusive oplock-break notifications to be acknowledged over direct TCP.");
                                TestAssertions.Equal(Smb2OplockLevel.None, watcherOpen.OplockLevel, "Expected the direct-TCP client open handle to adopt the lowered oplock level.");
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second direct-TCP open not to receive an oplock grant.");

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
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionDoesNotGrantExclusiveOplockWhenFileAlreadyHasOpen",
                        displayName: "Client connection does not grant an exclusive oplock when the file already has an open",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.None, firstOpen.OplockLevel, "Expected the first direct-TCP open without an oplock request not to receive an oplock grant.");

                                OpenCifsClientOpenHandle secondOpen = await secondClient.OpenAsync(
                                    secondTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.OplockLevel, "Expected a direct-TCP exclusive oplock request to be denied while the file already has an open.");

                                await secondClient.CloseAsync(secondOpen, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
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

        /// <summary>
        /// Build the high-level direct-TCP client facade suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientFacadeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Facade",
                displayName: "Client direct-TCP facade handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeTypesDoNotExposePreviewMarkers",
                        displayName: "Client facade types do not expose preview markers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsPreviewAttribute? facadePreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientFacade), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? directoryEntryPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientDirectoryEntry), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? fileMetadataPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClientFileMetadata), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (facadePreview != null)
                            {
                                throw new InvalidOperationException("Expected the managed high-level client facade to remain outside preview-only markers.");
                            }

                            if (directoryEntryPreview != null)
                            {
                                throw new InvalidOperationException("Expected high-level facade result types to remain outside preview-only markers.");
                            }

                            if (fileMetadataPreview != null)
                            {
                                throw new InvalidOperationException("Expected high-level facade metadata types to remain outside preview-only markers.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeTracksStableConnectionSurface",
                        displayName: "Client facade tracks the stable direct-TCP connection surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions());
                            TestAssertions.True(object.ReferenceEquals(client.Options, client.Session.Options), "Expected the facade and tracked session to share the same options instance.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeConnectsOverDirectTcpAndHandlesCommonOperations",
                        displayName: "Client facade connects over direct TCP and handles authenticated echo, directory create, file write, file read, and directory enumeration",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.EchoAsync(token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-network-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAllBytesAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the direct-TCP client facade to round-trip the file payload.");

                                OpenCifsClientDirectoryEntry[] directoryEntries = await client.EnumerateDirectoryAsync("public", "docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the direct-TCP client facade to enumerate the created file.");
                                TestAssertions.Equal("sample.txt", directoryEntries[0].FileName, "Unexpected direct-TCP directory entry name.");

                                string persistedPath = Path.Combine(sharePath, "docs", "sample.txt");
                                TestAssertions.True(File.Exists(persistedPath), "Expected the direct-TCP client facade to persist the file beneath the backing share.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesLargePayloadsOverBoundedCreditWindows",
                        displayName: "Client facade handles large payload reads and writes over direct TCP when the server credit window is bounded",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token, maximumCredits: 4).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = CreateLargePayloadBytes(400000);
                                await client.WriteAllBytesAsync("public", "docs\\large.bin", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAllBytesAsync("public", "docs\\large.bin", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the direct-TCP client facade to chunk and round-trip a payload larger than the bounded server credit window allows in a single SMB2 request.");

                                string persistedPath = Path.Combine(sharePath, "docs", "large.bin");
                                TestAssertions.True(File.Exists(persistedPath), "Expected the large payload to persist beneath the backing share.");
                                TestAssertions.Equal(expectedBytes.LongLength, new FileInfo(persistedPath).Length, "Expected the persisted large payload length to match the written client data.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesMetadataRenameAndDeleteOperationsOverDirectTcp",
                        displayName: "Client facade handles metadata query, rename, and file or empty-directory delete operations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-rename-delete-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);

                                OpenCifsClientFileMetadata fileMetadata = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal("docs\\sample.txt", fileMetadata.Path, "Unexpected file metadata path.");
                                TestAssertions.False(fileMetadata.IsDirectory, "Expected file metadata to report a file.");
                                TestAssertions.False(fileMetadata.IsDeletePending, "Expected new file metadata to report a non-delete-pending file.");
                                TestAssertions.Equal((ulong)expectedBytes.Length, fileMetadata.EndOfFile, "Unexpected file metadata EOF size.");

                                await client.RenameAsync("public", "docs\\sample.txt", "docs\\renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                byte[] renamedBytes = await client.ReadAllBytesAsync("public", "docs\\renamed.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, renamedBytes, "Expected the renamed file to preserve its payload.");

                                await client.RenameAsync("public", "docs", "archive", cancellationToken: token).ConfigureAwait(false);
                                OpenCifsClientFileMetadata directoryMetadata = await client.GetMetadataAsync("public", "archive", token).ConfigureAwait(false);
                                TestAssertions.Equal("archive", directoryMetadata.Path, "Unexpected directory metadata path.");
                                TestAssertions.True(directoryMetadata.IsDirectory, "Expected directory metadata to report a directory.");

                                await client.DeleteAsync("public", "archive\\renamed.txt", token).ConfigureAwait(false);
                                OpenCifsClientDirectoryEntry[] emptiedEntries = await client.EnumerateDirectoryAsync("public", "archive", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(0, emptiedEntries.Length, "Expected the renamed directory to be empty after deleting the file.");

                                await client.DeleteAsync("public", "archive", token).ConfigureAwait(false);

                                string renamedDirectoryPath = Path.Combine(sharePath, "archive");
                                string renamedFilePath = Path.Combine(sharePath, "archive", "renamed.txt");
                                TestAssertions.False(File.Exists(renamedFilePath), "Expected the deleted file to be removed from the backing share.");
                                TestAssertions.False(Directory.Exists(renamedDirectoryPath), "Expected the deleted directory to be removed from the backing share.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeHandlesBasicInfoAndEndOfFileMutationsOverDirectTcp",
                        displayName: "Client facade handles basic-info and file-length mutations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("facade-basic-info-data");
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", expectedBytes, token).ConfigureAwait(false);

                                DateTime expectedLastWriteUtc = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
                                await client.SetBasicInfoAsync(
                                    "public",
                                    "docs\\sample.txt",
                                    fileAttributes: FileAttributes.Hidden,
                                    lastWriteTimeUtc: expectedLastWriteUtc,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientFileMetadata metadataAfterBasicInfo = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True((metadataAfterBasicInfo.FileAttributes & FileAttributes.Hidden) != 0, "Expected the facade basic-info mutation to set the Hidden attribute.");
                                TestAssertions.Equal(expectedLastWriteUtc, metadataAfterBasicInfo.LastWriteTimeUtc!.Value, "Expected the facade basic-info mutation to preserve the requested last-write time.");

                                await client.SetFileLengthAsync("public", "docs\\sample.txt", 6, token).ConfigureAwait(false);
                                byte[] truncatedBytes = await client.ReadAllBytesAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                byte[] expectedTruncatedBytes = new byte[6];
                                Array.Copy(expectedBytes, expectedTruncatedBytes, expectedTruncatedBytes.Length);
                                TestAssertions.SequenceEqual(expectedTruncatedBytes, truncatedBytes, "Expected the facade file-length mutation to truncate the file.");

                                OpenCifsClientFileMetadata metadataAfterResize = await client.GetMetadataAsync("public", "docs\\sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(6UL, metadataAfterResize.EndOfFile, "Expected the facade file-length mutation to update EOF.");
                                TestAssertions.True((metadataAfterResize.FileAttributes & FileAttributes.Hidden) != 0, "Expected the Hidden attribute to remain set after the file-length mutation.");
                                TestAssertions.True(metadataAfterResize.LastWriteTimeUtc.HasValue, "Expected the facade metadata query to continue returning a last-write timestamp after the file-length mutation.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeCompletesDirectoryChangeNotifyOverDirectTcp",
                        displayName: "Client facade completes directory CHANGE_NOTIFY over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade watcherClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientFacade actorClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                notifyTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<OpenCifsClientChangeNotification[]> notifyTask = watcherClient.WaitForDirectoryChangeAsync(
                                    "public",
                                    "watched",
                                    FileNotifyChangeFilter.DirName,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.CreateDirectoryAsync("public", "watched\\child", token).ConfigureAwait(false);

                                OpenCifsClientChangeNotification[] entries = await notifyTask.ConfigureAwait(false);
                                TestAssertions.Equal(1, entries.Length, "Expected the facade CHANGE_NOTIFY surface to return a single directory-create entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected facade CHANGE_NOTIFY to surface directory creation as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child", entries[0].FileName, "Unexpected facade CHANGE_NOTIFY relative path.");

                                OpenCifsClientDirectoryEntry[] enumeratedEntries = await watcherClient.EnumerateDirectoryAsync("public", "watched", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, enumeratedEntries.Length, "Expected the watched directory to remain queryable after facade CHANGE_NOTIFY completion.");
                                TestAssertions.Equal("child", enumeratedEntries[0].FileName, "Unexpected watched-directory entry after facade CHANGE_NOTIFY completion.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeCancelsChangeNotifyForNonMatchingEventsOverDirectTcp",
                        displayName: "Client facade cancels CHANGE_NOTIFY for non-matching events over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade watcherClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientFacade actorClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await watcherClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                using CancellationTokenSource notifyTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                Task<OpenCifsClientChangeNotification[]> notifyTask = watcherClient.WaitForDirectoryChangeAsync(
                                    "public",
                                    "watched",
                                    FileNotifyChangeFilter.FileName,
                                    cancellationToken: notifyTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                await actorClient.SetBasicInfoAsync("public", "watched\\sample.txt", fileAttributes: FileAttributes.Hidden, cancellationToken: token).ConfigureAwait(false);

                                await Task.Delay(200, token).ConfigureAwait(false);
                                TestAssertions.False(notifyTask.IsCompleted, "Expected a metadata-only mutation to leave a filename-only facade CHANGE_NOTIFY request pending.");

                                notifyTokenSource.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    async () => await notifyTask.ConfigureAwait(false),
                                    "Expected cancelling the pending facade CHANGE_NOTIFY request to surface as OperationCanceledException.");

                                OpenCifsClientDirectoryEntry[] enumeratedEntries = await watcherClient.EnumerateDirectoryAsync("public", "watched", "*", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, enumeratedEntries.Length, "Expected the watched directory to remain queryable after cancelling facade CHANGE_NOTIFY.");
                                TestAssertions.Equal("sample.txt", enumeratedEntries[0].FileName, "Unexpected watched-directory entry after cancelling facade CHANGE_NOTIFY.");
                                TestAssertions.True((enumeratedEntries[0].FileAttributes & FileAttributes.Hidden) != 0, "Expected the non-matching metadata mutation to persist after cancelling facade CHANGE_NOTIFY.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsUseBeforeConnectAndBadCredentials",
                        displayName: "Client facade rejects operations before connect and rejects bad credentials over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            await using OpenCifsClientFacade disconnectedClient = new OpenCifsClientFacade(new OpenCifsClientOptions());
                            await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                () => disconnectedClient.EchoAsync(token),
                                "Expected authenticated direct-TCP operations to fail before connect.");

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade wrongPasswordClient = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                OpenCifsClientCredential wrongCredential = new OpenCifsClientCredential
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "WrongPassword!"
                                };

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => wrongPasswordClient.ConnectAsync(wrongCredential, token),
                                    "Expected the direct-TCP client facade to reject invalid credentials.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsNoOpBasicInfoAndDirectoryLengthMutationOverDirectTcp",
                        displayName: "Client facade rejects no-op basic-info requests and directory file-length mutations over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", System.Text.Encoding.UTF8.GetBytes("negative-basic-info-data"), token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<ArgumentException>(
                                    () => client.SetBasicInfoAsync("public", "docs\\sample.txt", cancellationToken: token),
                                    "Expected the facade basic-info mutation to reject a no-op request.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetFileLengthAsync("public", "docs", 1, token),
                                    "Expected the facade file-length mutation to reject directory paths.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.SetBasicInfoAsync("public", "docs\\missing.txt", fileAttributes: FileAttributes.Hidden, cancellationToken: token),
                                    "Expected the facade basic-info mutation to reject missing paths.");

                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected failed basic-info and file-length mutations to preserve the backing file.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Facade",
                        caseId: "ClientFacadeRejectsMissingMetadataAndNonEmptyDirectoryDeleteOverDirectTcp",
                        displayName: "Client facade rejects missing metadata queries and non-empty directory delete requests over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientFacade_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientFacade client = new OpenCifsClientFacade(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.CreateDirectoryAsync("public", "docs", token).ConfigureAwait(false);
                                await client.WriteAllBytesAsync("public", "docs\\sample.txt", System.Text.Encoding.UTF8.GetBytes("negative-facade-data"), token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.GetMetadataAsync("public", "docs\\missing.txt", token),
                                    "Expected metadata queries for missing paths to fail.");

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.DeleteAsync("public", "docs", token),
                                    "Expected delete requests for non-empty directories to fail.");

                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "docs", "sample.txt")), "Expected a failed non-empty directory delete to preserve the child file.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "docs")), "Expected a failed non-empty directory delete to preserve the directory.");
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

        /// <summary>
        /// Build the client locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientLockingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Locking",
                displayName: "Client byte-range locking",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Locking",
                        caseId: "ClientBuildsLockRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds SMB2 lock requests and accepts successful lock and unlock responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 610,
                                    VolatileFileId = 611,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2LockRequest lockRequest = session.CreateLockRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new Smb2LockElement
                                {
                                    Offset = 32,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                });
                            TestAssertions.Equal(1, lockRequest.Locks.Length, "Expected a single client lock element.");
                            TestAssertions.Equal(32UL, lockRequest.Locks[0].Offset, "Unexpected client lock offset.");
                            TestAssertions.Equal(8UL, lockRequest.Locks[0].Length, "Unexpected client lock length.");
                            TestAssertions.Equal(
                                Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately,
                                lockRequest.Locks[0].Flags,
                                "Unexpected client lock flags.");
                            session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2LockResponse());

                            Smb2LockRequest unlockRequest = session.CreateLockRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new Smb2LockElement
                                {
                                    Offset = 32,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                });
                            TestAssertions.Equal(Smb2LockFlags.Unlock, unlockRequest.Locks[0].Flags, "Unexpected client unlock flags.");
                            session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2LockResponse());
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Locking",
                        caseId: "ClientRejectsLockRequestsForUnknownOpenOrFailedStatus",
                        displayName: "Client rejects lock requests for unknown opens and throws on failed lock responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateLockRequest(
                                    1,
                                    2,
                                    new Smb2LockElement
                                    {
                                        Offset = 0,
                                        Length = 1,
                                        Flags = Smb2LockFlags.ExclusiveLock
                                    }),
                                "Lock requests should fail for an unknown open.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 620,
                                    VolatileFileId = 621,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.LockNotGranted, new Smb2LockResponse()),
                                "Failed lock results should throw.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client IOCTL suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientIoctlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Ioctl",
                displayName: "Client IOCTL handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Ioctl",
                        caseId: "ClientBuildsIoctlRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds open and wildcard SMB2 IOCTL requests and accepts successful responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 710,
                                    VolatileFileId = 711,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2IoctlRequest openRequest = session.CreateIoctlRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                (uint)FsctlCode.SrvEnumerateSnapshots,
                                inputBuffer: new byte[] { 0x10, 0x20 },
                                maxOutputResponse: 1024);
                            Smb2IoctlRequestValidator.Validate(openRequest);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, openRequest.CtlCode, "Unexpected client IOCTL control code.");
                            TestAssertions.Equal(Smb2IoctlFlags.IsFsctl, openRequest.Flags, "Unexpected client IOCTL flags.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20 }, openRequest.InputBuffer, "Unexpected client IOCTL input buffer.");

                            byte[] openOutput = session.ApplyIoctlResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = openState.PersistentFileId,
                                    VolatileFileId = openState.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new byte[] { 0x41, 0x42 },
                                    Flags = 0
                                });
                            TestAssertions.SequenceEqual(new byte[] { 0x41, 0x42 }, openOutput, "Unexpected client IOCTL output buffer.");

                            Smb2IoctlRequest connectionRequest = session.CreateConnectionIoctlRequest(
                                (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                maxOutputResponse: 2048);
                            Smb2IoctlRequestValidator.Validate(connectionRequest);
                            TestAssertions.Equal(UInt64.MaxValue, connectionRequest.PersistentFileId, "Expected wildcard IOCTL persistent file identifier.");
                            TestAssertions.Equal(UInt64.MaxValue, connectionRequest.VolatileFileId, "Expected wildcard IOCTL volatile file identifier.");

                            byte[] connectionOutput = session.ApplyConnectionIoctlResult(
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new byte[] { 0x99 },
                                    Flags = 0
                                });
                            TestAssertions.SequenceEqual(new byte[] { 0x99 }, connectionOutput, "Unexpected client wildcard IOCTL output buffer.");

                            Smb2IoctlRequest enumerateSnapshotsRequest = session.CreateEnumerateSnapshotsRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                maxOutputResponse: 256);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, enumerateSnapshotsRequest.CtlCode, "Unexpected snapshot-enumeration FSCTL code.");
                            SrvSnapshotArray snapshotArray = session.ApplyEnumerateSnapshotsResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = openState.PersistentFileId,
                                    VolatileFileId = openState.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new SrvSnapshotArray
                                    {
                                        NumberOfSnapshots = 0,
                                        Snapshots = Array.Empty<string>()
                                    }.ToByteArray(),
                                    Flags = 0
                                });
                            TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Unexpected client-observed snapshot count.");
                            TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected the bounded snapshot enumeration slice to allow an empty snapshot list.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Ioctl",
                        caseId: "ClientRejectsIoctlRequestsForUnknownOpenAndFailedStatus",
                        displayName: "Client rejects unknown-open IOCTL requests and throws on failed IOCTL responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateIoctlRequest(1, 2, (uint)FsctlCode.SrvEnumerateSnapshots),
                                "Open-scoped IOCTL requests should fail for an unknown open.");

                            OpenCifsClientSession negotiatedSession = CreateNegotiatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateConnectionIoctlRequest((uint)FsctlCode.QueryNetworkInterfaceInfo),
                                "Wildcard IOCTL requests should require an authenticated session.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 720,
                                    VolatileFileId = 721,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyIoctlResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    NtStatus.NotSupported,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = Array.Empty<byte>(),
                                        Flags = 0
                                    }),
                                "Failed open-scoped IOCTL results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyConnectionIoctlResult(
                                    NtStatus.NotSupported,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = Array.Empty<byte>(),
                                        Flags = 0
                                    }),
                                "Failed wildcard IOCTL results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyEnumerateSnapshotsResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots + 1,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new SrvSnapshotArray
                                        {
                                            NumberOfSnapshots = 0,
                                            Snapshots = Array.Empty<string>()
                                        }.ToByteArray(),
                                        Flags = 0
                                    }),
                                "Snapshot-enumeration results should reject unexpected FSCTL codes.");
                            return Task.CompletedTask;
                        })
                });
        }

        private static OpenCifsClientSession CreateNegotiatedClient(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER"
            });
            session.CreateNegotiateRequest();
            session.ApplyNegotiateResponse(new Smb2NegotiateResponse
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                Dialect = dialect,
                ServerGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f"),
                MaxTransactSize = 65536,
                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect),
                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect)
            });
            return session;
        }

        private static OpenCifsClientSession CreateAuthenticatedClient()
        {
            OpenCifsClientSession session = CreateNegotiatedClient();
            OpenCifsClientCredential credential = CreateCredential();
            session.CreateSessionSetupRequest(credential);
            session.CreateSessionAuthenticateRequest(
                credential,
                sessionId: 9,
                status: NtStatus.MoreProcessingRequired,
                challengeResponse: CreateChallengeResponse("LAB-SERVER", "WORKGROUP", Hex("0123456789ABCDEF")));
            session.ApplySessionSetupResult(9, NtStatus.Success, CreateSessionSetupSuccessResponse());
            return session;
        }

        private static OpenCifsClientSession CreateAuthenticatedTreeClient()
        {
            OpenCifsClientSession session = CreateAuthenticatedClient();
            session.ApplyTreeConnectResult("public", 42, NtStatus.Success, CreateTreeConnectSuccessResponse());
            return session;
        }

        private static (OpenCifsServerHost Host, OpenCifsClientSession Client, ulong SessionId) CreateAuthenticatedLoopbackPair()
        {
            OpenCifsServerHost host = CreateLoopbackServerHost();
            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER"
            });
            OpenCifsClientCredential credential = CreateCredential();
            Smb2NegotiateResponse negotiateResponse = host.HandleNegotiate(client.CreateNegotiateRequest());
            client.ApplyNegotiateResponse(negotiateResponse);

            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);
            return (host, client, successResult.SessionId);
        }

        private static OpenCifsServerHost CreateLoopbackServerHost()
        {
            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
            {
                ServerName = "LAB-SERVER"
            });
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = "public",
                RootPath = "SampleShare",
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            });
            return builder.BuildHost();
        }

        private static OpenCifsClientCredential CreateCredential()
        {
            return new OpenCifsClientCredential
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            };
        }

        private static Smb2SessionSetupResponse CreateChallengeResponse(string serverName, string userDomain, byte[] serverChallenge)
        {
            LittleEndianWriter timestampWriter = new LittleEndianWriter();
            timestampWriter.WriteUInt64(unchecked((ulong)DateTime.UtcNow.ToFileTimeUtc()));

            return new Smb2SessionSetupResponse
            {
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptIncomplete,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm,
                    ResponseToken = new NtlmChallengeMessage
                    {
                        Flags =
                            NtlmNegotiateFlags.Unicode |
                            NtlmNegotiateFlags.RequestTarget |
                            NtlmNegotiateFlags.Sign |
                            NtlmNegotiateFlags.Seal |
                            NtlmNegotiateFlags.AlwaysSign |
                            NtlmNegotiateFlags.Ntlm |
                            NtlmNegotiateFlags.ExtendedSessionSecurity |
                            NtlmNegotiateFlags.TargetInfo |
                            NtlmNegotiateFlags.TargetTypeServer |
                            NtlmNegotiateFlags.Key128 |
                            NtlmNegotiateFlags.Key56,
                        ServerChallenge = serverChallenge,
                        TargetName = serverName,
                        TargetInfo = new NtlmAvPair[]
                        {
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.NetBiosComputerName,
                                Value = System.Text.Encoding.Unicode.GetBytes(serverName)
                            },
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.NetBiosDomainName,
                                Value = System.Text.Encoding.Unicode.GetBytes(userDomain)
                            },
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.Timestamp,
                                Value = timestampWriter.ToArray()
                            }
                        }
                    }.ToByteArray()
                })
            };
        }

        private static Smb2SessionSetupResponse CreateSessionSetupSuccessResponse()
        {
            return new Smb2SessionSetupResponse
            {
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptCompleted,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm
                })
            };
        }

        private static Smb2TreeConnectResponse CreateTreeConnectSuccessResponse()
        {
            return new Smb2TreeConnectResponse
            {
                ShareType = Smb2ShareType.Disk,
                ShareFlags = 0,
                Capabilities = 0,
                MaximalAccess = 0x001F01FF
            };
        }

        private static Smb2Header CreateResponseHeader(Smb2Header requestHeader, ushort grantedCredits = 1, NtStatus status = NtStatus.Success, Smb2HeaderFlags flags = Smb2HeaderFlags.ServerToRedir, ushort creditCharge = 0, ulong asyncId = 0)
        {
            return new Smb2Header
            {
                CreditCharge = creditCharge,
                Status = status,
                Command = requestHeader.Command,
                CreditRequest = grantedCredits,
                Flags = flags,
                NextCommand = 0,
                MessageId = requestHeader.MessageId,
                TreeId = (flags & Smb2HeaderFlags.AsyncCommand) == 0 ? requestHeader.TreeId : 0,
                AsyncId = asyncId,
                SessionId = requestHeader.SessionId,
                Signature = new byte[16]
            };
        }

        private static void GrantCredits(OpenCifsClientSession session, ushort creditCount)
        {
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: creditCount);
            session.ApplyResponseHeader(CreateResponseHeader(requestHeader, grantedCredits: creditCount));
        }

        private static byte[] CreateLargePayloadBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)('A' + (index % 23)));
            }

            return bytes;
        }

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(string sharePath, int port, CancellationToken cancellationToken, int maximumCredits = 64)
        {
            DirectTcpPortReservation reservation = GetDirectTcpPortReservation(port);
            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = port,
                MaximumCredits = maximumCredits
            });
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = "public",
                RootPath = sharePath,
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            });

            OpenCifsDirectTcpServer server = builder.BuildDirectTcpServer();
            CancellationTokenSource serverCancellationTokenSource = new CancellationTokenSource();
            Task serverTask = server.RunAsync(serverCancellationTokenSource.Token);

            try
            {
                await WaitForDirectTcpServerAsync(reservation.Port, cancellationToken).ConfigureAwait(false);
                return (serverCancellationTokenSource, serverTask);
            }
            catch
            {
                serverCancellationTokenSource.Cancel();

                try
                {
                    await serverTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    serverCancellationTokenSource.Dispose();
                    ReleaseDirectTcpPortReservation();
                }

                throw;
            }
        }

        private static async Task StopDirectTcpServerAsync(CancellationTokenSource serverCancellationTokenSource, Task serverTask)
        {
            serverCancellationTokenSource.Cancel();

            try
            {
                await serverTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                serverCancellationTokenSource.Dispose();
                ReleaseDirectTcpPortReservation();
            }
        }

        private static async Task WaitForDirectTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < 40; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using TcpClient tcpClient = new TcpClient();

                try
                {
                    using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(250);
                    using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
                    await tcpClient.ConnectAsync(IPAddress.Loopback, port, linkedTokenSource.Token).ConfigureAwait(false);
                    return;
                }
                catch (SocketException)
                {
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            throw new InvalidOperationException("Timed out waiting for the direct-TCP test server to accept connections.");
        }

        private static int AllocateTcpPort()
        {
            if (_CurrentDirectTcpPortReservation.Value != null)
            {
                throw new InvalidOperationException("A direct-TCP test port is already reserved on this async flow.");
            }

            Semaphore? semaphore = new Semaphore(initialCount: 1, maximumCount: 1, name: DirectTcpPortReservationSemaphoreName);
            bool lockTaken = false;

            try
            {
                lockTaken = semaphore.WaitOne(TimeSpan.FromSeconds(30));

                if (!lockTaken)
                {
                    throw new InvalidOperationException("Timed out waiting to reserve the shared direct-TCP test port allocator.");
                }

                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();

                try
                {
                    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    _CurrentDirectTcpPortReservation.Value = new DirectTcpPortReservation(semaphore, port);
                    semaphore = null;
                    return port;
                }
                finally
                {
                    listener.Stop();
                }
            }
            catch
            {
                if (semaphore != null)
                {
                    if (lockTaken)
                    {
                        semaphore.Release();
                    }

                    semaphore.Dispose();
                }

                throw;
            }
        }

        private static DirectTcpPortReservation GetDirectTcpPortReservation(int port)
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;

            if (reservation == null || reservation.Port != port)
            {
                throw new InvalidOperationException("Expected a reserved direct-TCP test port before starting the server.");
            }

            return reservation;
        }

        private static void ReleaseDirectTcpPortReservation()
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;
            _CurrentDirectTcpPortReservation.Value = null;

            if (reservation == null)
            {
                return;
            }

            reservation.Semaphore.Release();
            reservation.Semaphore.Dispose();
        }

        private sealed class DirectTcpPortReservation
        {
            public DirectTcpPortReservation(Semaphore semaphore, int port)
            {
                Semaphore = semaphore ?? throw new ArgumentNullException(nameof(semaphore));
                Port = port;
            }

            public Semaphore Semaphore { get; }

            public int Port { get; }
        }

        private static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }
    }
}

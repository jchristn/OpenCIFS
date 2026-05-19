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
    internal static class ServerSessionTreeSuiteBuilder
    {
        /// <summary>
        /// Build the server session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerSessionTreeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.SessionTree",
                displayName: "Server session and tree handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerAuthenticatesKnownAccountAndHandlesTreeLifecycle",
                        displayName: "Server issues a challenge, authenticates a known account, and handles tree lifecycle operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            Smb2SessionSetupRequest initialRequest = CreateInitialSessionSetupRequest("alice", "WORKGROUP");
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, initialRequest);

                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the first session-setup leg to return a challenge.");
                            TestAssertions.True(challengeResult.SessionId != 0, "Expected the server to assign a non-zero session identifier.");

                            Smb2SessionSetupRequest authenticateRequest = CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult);
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected the server to accept valid NTLMv2 credentials.");

                            SpnegoNegTokenResp successToken = SpnegoTokenCodec.DecodeNegTokenResp(successResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptCompleted, successToken.NegotiationState!.Value, "Expected the server to complete SPNEGO after authentication.");
                            TestAssertions.True(successToken.MechanismListMic == null, "Expected the legacy OpenCIFS NTLM SPNEGO success token to omit the mechListMIC field in the bounded compatibility path.");

                            Smb2TreeConnectRequest treeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Path = "\\\\LAB-SERVER\\public"
                            };
                            OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(successResult.SessionId, treeConnectRequest);

                            TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected the authenticated session to connect to the configured share.");
                            TestAssertions.True(treeConnectResult.TreeId != 0, "Expected the server to assign a non-zero tree identifier.");

                            OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = host.HandleTreeDisconnect(
                                successResult.SessionId,
                                treeConnectResult.TreeId,
                                new Smb2TreeDisconnectRequest());
                            TestAssertions.Equal(NtStatus.Success, treeDisconnectResult.Status, "Expected tree disconnect to succeed.");

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = host.HandleLogoff(successResult.SessionId, new Smb2LogoffRequest());
                            TestAssertions.Equal(NtStatus.Success, logoffResult.Status, "Expected logoff to succeed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerSignsLogoffResponseAfterSessionCleanupAndRejectsLaterSessionReuse",
                        displayName: "Server signs a logoff response after session cleanup and rejects later session reuse",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            AuthenticatedSigningContext signingContext = AuthenticateSessionAndGetSigningKey(host);
                            ulong sessionId = signingContext.SessionId;
                            byte[] signingKey = signingContext.SigningKey;
                            Smb2LogoffRequest logoffRequest = new Smb2LogoffRequest();
                            Smb2Header signedLogoffHeader = CreateRequestHeader(
                                Smb2Command.Logoff,
                                messageId: 0,
                                flags: Smb2HeaderFlags.Signed,
                                sessionId: sessionId);
                            Smb2HeaderValidator.Validate(signedLogoffHeader);

                            byte[] signedLogoffRequestBytes = CreateSignedPacketBytes(signedLogoffHeader, logoffRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket signedLogoffRequestPacket = Smb2CompoundPacket.ReadFrom(signedLogoffRequestBytes);
                            host.ValidateRequestPacket(signedLogoffRequestPacket, signedLogoffRequestBytes);
                            host.ValidateAndAcceptRequestHeader(signedLogoffHeader, Smb2Command.Logoff, expectedSessionId: sessionId);

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = host.HandleLogoff(sessionId, logoffRequest);
                            TestAssertions.Equal(NtStatus.Success, logoffResult.Status, "Expected logoff to succeed before response finalization.");

                            Smb2Header responseHeader = host.CreateResponseHeader(signedLogoffHeader, logoffResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, logoffResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            Smb2Header parsedResponseHeader = parsedResponsePacket.Entries[0].Header;

                            TestAssertions.True(
                                (parsedResponseHeader.Flags & Smb2HeaderFlags.Signed) != 0,
                                "Expected the logoff response to preserve the Signed flag when the client signed the request.");

                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponseHeader.Signature),
                                "Expected the finalized logoff response signature to verify with the authenticated session signing key.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> postLogoffEchoResult = host.HandleEcho(sessionId, new Smb2EchoRequest());
                            TestAssertions.Equal(
                                NtStatus.AccessDenied,
                                postLogoffEchoResult.Status,
                                "Expected the server to deny further session use after logoff even though the response stayed signable.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerCompletesStandardSpnegoWrappedNtlmSessionSetup",
                        displayName: "Server completes a standard SPNEGO-wrapped NTLM session setup with an accept-completed final token",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            Smb2SessionSetupRequest initialRequest = CreateStandardInitialSessionSetupRequest("alice", "WORKGROUP");
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, initialRequest);

                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the first standard NTLM session-setup leg to return a challenge.");
                            TestAssertions.True(challengeResult.SessionId != 0, "Expected the server to assign a non-zero standard session identifier.");

                            SpnegoNegTokenResp challengeToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, challengeToken.NegotiationState!.Value, "Expected the standard challenge leg to return an incomplete SPNEGO token.");
                            TestAssertions.True(challengeToken.ResponseToken != null && challengeToken.ResponseToken.Length != 0, "Expected the standard challenge leg to carry an NTLM challenge token.");

                            Smb2SessionSetupRequest authenticateRequest = CreateStandardAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult);
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected the server to accept valid standard SPNEGO-wrapped NTLM credentials.");
                            TestAssertions.True(successResult.Response.SecurityBuffer.Length != 0, "Expected the standard NTLM success leg to carry a final SPNEGO token.");

                            SpnegoNegTokenResp successToken = SpnegoTokenCodec.DecodeNegTokenResp(successResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptCompleted, successToken.NegotiationState!.Value, "Expected the standard NTLM success leg to complete SPNEGO.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, successToken.SupportedMechanism, "Expected the standard NTLM success leg to identify NTLM as the selected mechanism.");
                            TestAssertions.True(successToken.MechanismListMic != null && successToken.MechanismListMic.Length == 16, "Expected the standard NTLM success leg to include a mechListMIC when the authenticate leg carries an NTLM MIC.");

                            SpnegoNegTokenResp authenticateToken = SpnegoTokenCodec.DecodeNegTokenResp(authenticateRequest.SecurityBuffer);
                            NtlmAuthenticateMessage authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateToken.ResponseToken!);
                            byte[] expectedMechanismListMic = CreateExpectedSpnegoMechanismListMic(
                                new[] { SpnegoMechanismOid.Ntlm },
                                authenticateMessage.Flags,
                                ExtractSessionBaseKey("alice", "WORKGROUP", "Password123!", challengeResult));
                            TestAssertions.SequenceEqual(expectedMechanismListMic, successToken.MechanismListMic!, "Expected the standard NTLM success leg mechListMIC to stay stable.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRoutesExplicitShareRegistrationsAcrossSeparateRoots",
                        displayName: "Server routes authenticated tree connects across explicit share registrations and persists creates in the selected root",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsServerShares_" + Guid.NewGuid().ToString("N"));
                            string legacyPath = Path.Combine(rootPath, "legacy");
                            string publicPath = Path.Combine(rootPath, "public");
                            string archivePath = Path.Combine(rootPath, "archive");
                            Directory.CreateDirectory(publicPath);
                            Directory.CreateDirectory(archivePath);

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER",
                                    ShareName = "legacy",
                                    SharePath = legacyPath
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = publicPath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "archive",
                                    RootPath = archivePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                ulong sessionId = AuthenticateSession(host);
                                OpenCifsServerTreeConnectResult archiveTreeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\archive"
                                    });

                                TestAssertions.Equal(NtStatus.Success, archiveTreeConnectResult.Status, "Expected the server to route the tree connect to an explicitly registered share.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    archiveTreeConnectResult.TreeId,
                                    CreateFileCreateRequest("builder.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected create to succeed on the selected registered share.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    archiveTreeConnectResult.TreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected close to succeed after the routed create.");

                                TestAssertions.True(File.Exists(Path.Combine(archivePath, "builder.txt")), "Expected the created file to land in the selected registered share root.");
                                TestAssertions.False(File.Exists(Path.Combine(publicPath, "builder.txt")), "Expected the routed create to avoid sibling registered share roots.");

                                OpenCifsServerTreeConnectResult legacyFallbackResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\legacy"
                                    });
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, legacyFallbackResult.Status, "Expected explicit share registrations to suppress the implicit legacy options share.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsBadPasswordAndUnauthenticatedTreeConnect",
                        displayName: "Server rejects invalid credentials and unauthenticated tree access",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerTreeConnectResult unauthenticatedTreeConnectResult = host.HandleTreeConnect(
                                sessionId: 0,
                                request: new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\public"
                                });
                            TestAssertions.Equal(NtStatus.AccessDenied, unauthenticatedTreeConnectResult.Status, "Expected unauthenticated tree connect to be denied.");

                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            Smb2SessionSetupRequest badPasswordRequest = CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "WrongPassword!", challengeResult);
                            OpenCifsServerSessionSetupResult failedAuthenticationResult = host.HandleSessionSetup(challengeResult.SessionId, badPasswordRequest);

                            TestAssertions.Equal(NtStatus.AccessDenied, failedAuthenticationResult.Status, "Expected the server to reject an invalid password.");

                            OpenCifsServerTreeConnectResult postFailureTreeConnectResult = host.HandleTreeConnect(
                                challengeResult.SessionId,
                                new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\public"
                                });
                            TestAssertions.Equal(NtStatus.AccessDenied, postFailureTreeConnectResult.Status, "Expected the failed session to lose tree access.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsUnknownShareAfterAuthentication",
                        displayName: "Server returns ObjectNameNotFound for unknown shares after authentication succeeds",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(
                                challengeResult.SessionId,
                                CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult));

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authentication to succeed before validating share lookup.");

                            OpenCifsServerTreeConnectResult missingShareResult = host.HandleTreeConnect(
                                successResult.SessionId,
                                new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\missing"
                                });
                            TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingShareResult.Status, "Expected the server to reject unknown shares.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsDuplicateExplicitShareRegistrations",
                        displayName: "Server builder rejects duplicate explicit filesystem share registrations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsDuplicateShares_" + Guid.NewGuid().ToString("N"));
                            string firstSharePath = Path.Combine(rootPath, "first");
                            string secondSharePath = Path.Combine(rootPath, "second");
                            Directory.CreateDirectory(firstSharePath);
                            Directory.CreateDirectory(secondSharePath);

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = firstSharePath,
                                    CreateRootIfMissing = true
                                });

                                try
                                {
                                    builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                    {
                                        ShareName = "PUBLIC",
                                        RootPath = secondSharePath,
                                        CreateRootIfMissing = true
                                    });
                                }
                                catch (OpenCifsServerConfigurationException)
                                {
                                    return Task.CompletedTask;
                                }

                                throw new InvalidOperationException("Expected duplicate share registration to be rejected.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerAuthenticatesSessionsAndRejectsTreeConnectsThroughCallbacks",
                        displayName: "Server callback hooks authenticate sessions through the builder surface and reject selected tree connects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsCallbackSessions_" + Guid.NewGuid().ToString("N"));
                            string sharePath = Path.Combine(rootPath, "public");
                            string blockedSharePath = Path.Combine(rootPath, "blocked");
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(blockedSharePath);
                            int authenticatedCallbackCount = 0;
                            OpenCifsServerAuthenticatedSessionContext? authenticatedContext = null;
                            int treeConnectCallbackCount = 0;
                            OpenCifsServerTreeConnectContext? treeConnectContext = null;

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "blocked",
                                    RootPath = blockedSharePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });
                                builder.ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
                                {
                                    AuthenticatedSessionCallback = context =>
                                    {
                                        authenticatedCallbackCount++;
                                        authenticatedContext = context;
                                        return null;
                                    },
                                    TreeConnectCallback = context =>
                                    {
                                        treeConnectCallbackCount++;
                                        treeConnectContext = context;
                                        return string.Equals(context.ShareName, "blocked", StringComparison.OrdinalIgnoreCase)
                                            ? NtStatus.AccessDenied
                                            : null;
                                    }
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                ulong sessionId = AuthenticateSession(host);

                                TestAssertions.Equal(1, authenticatedCallbackCount, "Expected the authenticated-session callback to run exactly once.");
                                TestAssertions.True(authenticatedContext != null, "Expected the authenticated-session callback context to be captured.");
                                TestAssertions.Equal(sessionId, authenticatedContext!.SessionId, "Expected the callback to observe the assigned session identifier.");
                                TestAssertions.Equal("alice", authenticatedContext.UserName, "Expected the callback to observe the authenticated user name.");
                                TestAssertions.Equal("WORKGROUP", authenticatedContext.UserDomain, "Expected the callback to observe the authenticated user domain.");
                                TestAssertions.Equal("LegacyOpenCifs", authenticatedContext.AuthenticationFlavor, "Expected the shared authentication helper to use the current legacy OpenCIFS session-setup path.");

                                OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\blocked"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, treeConnectResult.Status, "Expected the tree-connect callback to reject the request.");
                                TestAssertions.Equal(1, treeConnectCallbackCount, "Expected the tree-connect callback to run exactly once.");
                                TestAssertions.True(treeConnectContext != null, "Expected the tree-connect callback context to be captured.");
                                TestAssertions.Equal(sessionId, treeConnectContext!.SessionId, "Expected the tree-connect callback to observe the authenticated session.");
                                TestAssertions.Equal("blocked", treeConnectContext.ShareName, "Expected the tree-connect callback to observe the resolved share name.");
                                TestAssertions.Equal(blockedSharePath, treeConnectContext.ShareRootPath, "Expected the tree-connect callback to observe the resolved share root.");
                                TestAssertions.Equal("\\\\LAB-SERVER\\blocked", treeConnectContext.Request.Path, "Expected the tree-connect callback to observe the requested UNC path.");

                                treeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected the allowed tree connect to succeed after the blocked-share rejection.");
                                TestAssertions.Equal(2, treeConnectCallbackCount, "Expected the tree-connect callback to run again for the allowed share.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> shareRootOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeConnectResult.TreeId,
                                    new Smb2CreateRequest
                                    {
                                        RequestedOplockLevel = Smb2OplockLevel.None,
                                        ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                        DesiredAccess = 0x80000080U,
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Directory,
                                        ShareAccess = 0x00000007U,
                                        CreateDisposition = Smb2CreateDisposition.Open,
                                        CreateOptions = Smb2CreateOptions.OpenReparsePoint,
                                        Name = string.Empty,
                                        CreateContexts = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, shareRootOpenResult.Status, "Expected empty-name share-root opens to succeed for the bounded Windows-compatible slice.");
                                TestAssertions.True((shareRootOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected empty-name share-root opens to resolve to a directory.");

                                TestAssertions.Throws<ProtocolValidationException>(
                                    () => host.HandleCreate(
                                        sessionId,
                                        treeConnectResult.TreeId,
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.None,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x80000080U,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.Open,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = string.Empty,
                                            CreateContexts = Array.Empty<byte>()
                                        }),
                                    "Expected empty-name create requests that demand non-directory opens to remain rejected.");

                                OpenCifsServerHostBuilder rejectingBuilder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                rejectingBuilder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                rejectingBuilder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });
                                rejectingBuilder.ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
                                {
                                    AuthenticatedSessionCallback = _ => NtStatus.AccessDenied
                                });

                                OpenCifsServerHost rejectingHost = rejectingBuilder.BuildHost();
                                OpenCifsServerSessionSetupResult challengeResult = rejectingHost.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                                OpenCifsServerSessionSetupResult rejectedAuthenticationResult = rejectingHost.HandleSessionSetup(
                                    challengeResult.SessionId,
                                    CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult));
                                TestAssertions.Equal(NtStatus.AccessDenied, rejectedAuthenticationResult.Status, "Expected the authenticated-session callback to reject the completed session.");

                                OpenCifsServerTreeConnectResult rejectedTreeConnectResult = rejectingHost.HandleTreeConnect(
                                    challengeResult.SessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, rejectedTreeConnectResult.Status, "Expected rejected authenticated sessions to remain unusable for tree connect.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }
    }
}

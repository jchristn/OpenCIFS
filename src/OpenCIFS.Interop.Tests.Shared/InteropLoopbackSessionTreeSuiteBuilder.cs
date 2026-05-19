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
    internal static class InteropLoopbackSessionTreeSuiteBuilder
    {
        /// <summary>
        /// Build the loopback session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor LoopbackSessionTreeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackSessionTree",
                displayName: "Loopback session and tree coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerCompleteSessionAndTreeLifecycle",
                        displayName: "Client and server loopback complete session setup, tree connect, tree disconnect, and logoff",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();

                            Smb2SessionSetupRequest initialRequest = client.CreateSessionSetupRequest(credential);
                            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, initialRequest);
                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the first session-setup leg to challenge.");

                            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                                credential,
                                challengeResult.SessionId,
                                challengeResult.Status,
                                challengeResult.Response);
                            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
                            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

                            TestAssertions.True(client.IsAuthenticated, "Expected loopback authentication to complete successfully.");
                            TestAssertions.True(client.SessionId == successResult.SessionId, "Expected the client to retain the server-assigned session identifier.");

                            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("public");
                            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(client.SessionId!.Value, treeConnectRequest);
                            client.ApplyTreeConnectResult("public", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree after loopback tree connect.");

                            uint treeId = client.ConnectedTreeIds[0];
                            OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = server.HandleTreeDisconnect(
                                client.SessionId!.Value,
                                treeId,
                                client.CreateTreeDisconnectRequest(treeId));
                            client.ApplyTreeDisconnectResult(treeId, treeDisconnectResult.Status, treeDisconnectResult.Response);

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = server.HandleLogoff(
                                client.SessionId!.Value,
                                client.CreateLogoffRequest());
                            client.ApplyLogoffResult(logoffResult.Status, logoffResult.Response);

                            TestAssertions.False(client.IsAuthenticated, "Expected logoff to clear loopback authentication state.");
                            TestAssertions.Equal(0, client.ConnectedTreeIds.Length, "Expected logoff to leave no connected trees.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerCompleteSessionAndTreeLifecycleUnderOptInSmb302",
                        displayName: "Client and server loopback complete session setup, tree connect, tree disconnect, and logoff under opt-in SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost(maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: false);
                            OpenCifsClientSession client = CreateClient(maximumDialect: SmbDialect.Smb302, preferEncryption: false);
                            OpenCifsClientCredential credential = CreateCredential();

                            Smb2NegotiateRequest negotiateRequest = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse negotiateResponse = server.HandleNegotiate(negotiateRequest);
                            client.ApplyNegotiateResponse(negotiateResponse);

                            Smb2SessionSetupRequest initialRequest = client.CreateSessionSetupRequest(credential);
                            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, initialRequest);
                            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                                credential,
                                challengeResult.SessionId,
                                challengeResult.Status,
                                challengeResult.Response);
                            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
                            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

                            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest(TestEnvironmentDefaults.DefaultShareName);
                            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(client.SessionId!.Value, treeConnectRequest);
                            client.ApplyTreeConnectResult(TestEnvironmentDefaults.DefaultShareName, treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                            TestAssertions.Equal(SmbDialect.Smb302, client.NegotiatedDialect!.Value, "Expected the authenticated loopback flow to remain on SMB 3.0.2.");
                            TestAssertions.True(client.IsAuthenticated, "Expected the opt-in SMB 3.0.2 loopback session to authenticate successfully.");
                            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree under the opt-in SMB 3.0.2 loopback flow.");

                            uint treeId = client.ConnectedTreeIds[0];
                            OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = server.HandleTreeDisconnect(
                                client.SessionId!.Value,
                                treeId,
                                client.CreateTreeDisconnectRequest(treeId));
                            client.ApplyTreeDisconnectResult(treeId, treeDisconnectResult.Status, treeDisconnectResult.Response);

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = server.HandleLogoff(
                                client.SessionId!.Value,
                                client.CreateLogoffRequest());
                            client.ApplyLogoffResult(logoffResult.Status, logoffResult.Response);

                            TestAssertions.False(client.IsAuthenticated, "Expected logoff to clear opt-in SMB 3.0.2 authentication state.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerCompleteEncryptedSessionTreeAndEchoLifecycleUnderSmb302",
                        displayName: "Client and server loopback complete encrypted SMB 3.0.2 session, echo, tree, and logoff lifecycle through transform packets",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost(maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);
                            OpenCifsClientSession client = CreateClient(maximumDialect: SmbDialect.Smb302, preferEncryption: true);
                            OpenCifsClientCredential credential = CreateCredential();

                            Smb2NegotiateRequest negotiateRequest = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse negotiateResponse = server.HandleNegotiate(negotiateRequest);
                            client.ApplyNegotiateResponse(negotiateResponse);
                            TestAssertions.Equal(SmbDialect.Smb302, client.NegotiatedDialect!.Value, "Expected encrypted loopback negotiation to select SMB 3.0.2.");
                            TestAssertions.True((negotiateResponse.Capabilities & Smb2GlobalCapabilities.Encryption) != 0, "Expected the encrypted loopback negotiate response to advertise encryption capability.");

                            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
                            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(
                                challengeResult.SessionId,
                                client.CreateSessionAuthenticateRequest(
                                    credential,
                                    challengeResult.SessionId,
                                    challengeResult.Status,
                                    challengeResult.Response));
                            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

                            TestAssertions.True((successResult.Response.SessionFlags & Smb2SessionFlags.EncryptData) != 0, "Expected the SMB3 session-setup success response to require encryption.");
                            TestAssertions.True(client.IsSessionEncryptionRequired, "Expected the authenticated SMB3 loopback session to require encryption.");

                            Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: client.SessionId!.Value);
                            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest(TestEnvironmentDefaults.DefaultShareName);
                            Smb2CompoundPacket treeConnectRequestPacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(treeConnectHeader, treeConnectRequest.ToByteArray())
                            });
                            byte[] encryptedTreeConnectBytes = client.FinalizeRequestPacket(treeConnectRequestPacket);
                            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedTreeConnectBytes), "Expected the encrypted loopback tree connect request to use an SMB3 transform header.");
                            byte[] decryptedTreeConnectBytes = server.UnwrapRequestPacket(encryptedTreeConnectBytes, out bool treeConnectWasEncrypted);
                            TestAssertions.True(treeConnectWasEncrypted, "Expected the server to recognize the encrypted loopback tree connect request.");
                            Smb2CompoundPacket parsedTreeConnectPacket = Smb2CompoundPacket.ReadFrom(decryptedTreeConnectBytes);
                            server.ValidateRequestPacket(parsedTreeConnectPacket, decryptedTreeConnectBytes, treeConnectWasEncrypted);
                            server.ValidateAndAcceptRequestHeader(parsedTreeConnectPacket.Entries[0].Header, Smb2Command.TreeConnect, expectedSessionId: client.SessionId.Value);
                            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(client.SessionId.Value, treeConnectRequest);
                            byte[] encryptedTreeConnectResponseBytes = server.FinalizeResponsePacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: client.SessionId.Value, treeId: treeConnectResult.TreeId),
                                        treeConnectResult.Response.ToByteArray())
                                }));
                            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedTreeConnectResponseBytes), "Expected the encrypted loopback tree connect response to use an SMB3 transform header.");
                            byte[] decryptedTreeConnectResponseBytes = client.UnwrapResponsePacket(encryptedTreeConnectResponseBytes);
                            Smb2CompoundPacket parsedTreeConnectResponsePacket = Smb2CompoundPacket.ReadFrom(decryptedTreeConnectResponseBytes);
                            client.ValidateResponsePacket(parsedTreeConnectResponsePacket, decryptedTreeConnectResponseBytes);
                            client.ApplyResponseHeader(parsedTreeConnectResponsePacket.Entries[0].Header);
                            client.ApplyTreeConnectResult(TestEnvironmentDefaults.DefaultShareName, treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                            uint treeId = client.ConnectedTreeIds[0];
                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, treeId, sessionId: client.SessionId.Value);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            byte[] encryptedEchoBytes = client.FinalizeRequestPacket(new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(echoHeader, echoRequest.ToByteArray())
                            }));
                            byte[] decryptedEchoBytes = server.UnwrapRequestPacket(encryptedEchoBytes, out bool echoWasEncrypted);
                            TestAssertions.True(echoWasEncrypted, "Expected the server to recognize the encrypted loopback echo request.");
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(decryptedEchoBytes);
                            server.ValidateRequestPacket(parsedEchoPacket, decryptedEchoBytes, echoWasEncrypted);
                            server.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(client.SessionId.Value, echoRequest);
                            byte[] encryptedEchoResponseBytes = server.FinalizeResponsePacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        server.CreateResponseHeader(echoHeader, echoResult.Status, sessionId: client.SessionId.Value, treeId: treeId),
                                        echoResult.Response.ToByteArray())
                                }));
                            byte[] decryptedEchoResponseBytes = client.UnwrapResponsePacket(encryptedEchoResponseBytes);
                            Smb2CompoundPacket parsedEchoResponsePacket = Smb2CompoundPacket.ReadFrom(decryptedEchoResponseBytes);
                            client.ValidateResponsePacket(parsedEchoResponsePacket, decryptedEchoResponseBytes);
                            client.ApplyResponseHeader(parsedEchoResponsePacket.Entries[0].Header);
                            client.ApplyEchoResult(echoResult.Status, Smb2EchoResponse.ReadFrom(parsedEchoResponsePacket.Entries[0].Payload));

                            Smb2Header treeDisconnectHeader = client.CreateRequestHeader(Smb2Command.TreeDisconnect, treeId, sessionId: client.SessionId.Value);
                            Smb2TreeDisconnectRequest treeDisconnectRequest = client.CreateTreeDisconnectRequest(treeId);
                            byte[] encryptedTreeDisconnectBytes = client.FinalizeRequestPacket(new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(treeDisconnectHeader, treeDisconnectRequest.ToByteArray())
                            }));
                            byte[] decryptedTreeDisconnectBytes = server.UnwrapRequestPacket(encryptedTreeDisconnectBytes, out bool treeDisconnectWasEncrypted);
                            TestAssertions.True(treeDisconnectWasEncrypted, "Expected the server to recognize the encrypted loopback tree disconnect request.");
                            Smb2CompoundPacket parsedTreeDisconnectPacket = Smb2CompoundPacket.ReadFrom(decryptedTreeDisconnectBytes);
                            server.ValidateRequestPacket(parsedTreeDisconnectPacket, decryptedTreeDisconnectBytes, treeDisconnectWasEncrypted);
                            server.ValidateAndAcceptRequestHeader(parsedTreeDisconnectPacket.Entries[0].Header, Smb2Command.TreeDisconnect, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                            OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = server.HandleTreeDisconnect(client.SessionId.Value, treeId, treeDisconnectRequest);
                            byte[] encryptedTreeDisconnectResponseBytes = server.FinalizeResponsePacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        server.CreateResponseHeader(treeDisconnectHeader, treeDisconnectResult.Status, sessionId: client.SessionId.Value, treeId: treeId),
                                        treeDisconnectResult.Response.ToByteArray())
                                }));
                            byte[] decryptedTreeDisconnectResponseBytes = client.UnwrapResponsePacket(encryptedTreeDisconnectResponseBytes);
                            Smb2CompoundPacket parsedTreeDisconnectResponsePacket = Smb2CompoundPacket.ReadFrom(decryptedTreeDisconnectResponseBytes);
                            client.ValidateResponsePacket(parsedTreeDisconnectResponsePacket, decryptedTreeDisconnectResponseBytes);
                            client.ApplyResponseHeader(parsedTreeDisconnectResponsePacket.Entries[0].Header);
                            client.ApplyTreeDisconnectResult(treeId, treeDisconnectResult.Status, treeDisconnectResult.Response);

                            Smb2Header logoffHeader = client.CreateRequestHeader(Smb2Command.Logoff, sessionId: client.SessionId.Value);
                            Smb2LogoffRequest logoffRequest = client.CreateLogoffRequest();
                            byte[] encryptedLogoffBytes = client.FinalizeRequestPacket(new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(logoffHeader, logoffRequest.ToByteArray())
                            }));
                            byte[] decryptedLogoffBytes = server.UnwrapRequestPacket(encryptedLogoffBytes, out bool logoffWasEncrypted);
                            TestAssertions.True(logoffWasEncrypted, "Expected the server to recognize the encrypted loopback logoff request.");
                            Smb2CompoundPacket parsedLogoffPacket = Smb2CompoundPacket.ReadFrom(decryptedLogoffBytes);
                            server.ValidateRequestPacket(parsedLogoffPacket, decryptedLogoffBytes, logoffWasEncrypted);
                            server.ValidateAndAcceptRequestHeader(parsedLogoffPacket.Entries[0].Header, Smb2Command.Logoff, expectedSessionId: client.SessionId.Value);
                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = server.HandleLogoff(client.SessionId.Value, logoffRequest);
                            byte[] encryptedLogoffResponseBytes = server.FinalizeResponsePacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        server.CreateResponseHeader(logoffHeader, logoffResult.Status, sessionId: logoffHeader.SessionId),
                                        logoffResult.Response.ToByteArray())
                                }));
                            byte[] decryptedLogoffResponseBytes = client.UnwrapResponsePacket(encryptedLogoffResponseBytes);
                            Smb2CompoundPacket parsedLogoffResponsePacket = Smb2CompoundPacket.ReadFrom(decryptedLogoffResponseBytes);
                            client.ValidateResponsePacket(parsedLogoffResponsePacket, decryptedLogoffResponseBytes);
                            client.ApplyResponseHeader(parsedLogoffResponsePacket.Entries[0].Header);
                            client.ApplyLogoffResult(logoffResult.Status, logoffResult.Response);

                            TestAssertions.False(client.IsAuthenticated, "Expected encrypted loopback logoff to clear the authenticated client session.");
                            TestAssertions.Equal(0, client.ConnectedTreeIds.Length, "Expected encrypted loopback logoff to leave no connected trees.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerRejectBadPassword",
                        displayName: "Client and server loopback reject invalid credentials during session setup",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = new OpenCifsClientCredential
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                Password = "WrongPassword!"
                            };

                            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
                            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                                credential,
                                challengeResult.SessionId,
                                challengeResult.Status,
                                challengeResult.Response);
                            OpenCifsServerSessionSetupResult failureResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);

                            TestAssertions.Equal(NtStatus.AccessDenied, failureResult.Status, "Expected loopback session setup to reject the wrong password.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerRejectUnknownShare",
                        displayName: "Client and server loopback reject an unknown share after authentication succeeds",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();

                            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
                            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(
                                challengeResult.SessionId,
                                client.CreateSessionAuthenticateRequest(
                                    credential,
                                    challengeResult.SessionId,
                                    challengeResult.Status,
                                    challengeResult.Response));
                            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

                            OpenCifsServerTreeConnectResult missingShareResult = server.HandleTreeConnect(
                                client.SessionId!.Value,
                                client.CreateTreeConnectRequest("missing"));
                            TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingShareResult.Status, "Expected loopback tree connect to reject unknown shares.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerConnectToExplicitRegisteredSharesAcrossSeparateRoots",
                        displayName: "Client and server loopback connect to explicit registered shares across separate roots",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropShares_" + Guid.NewGuid().ToString("N"));
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

                                OpenCifsServerHost server = builder.BuildHost();
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                                OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(
                                    sessionId,
                                    client.CreateTreeConnectRequest("archive"));
                                client.ApplyTreeConnectResult("archive", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);
                                TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected loopback tree connect to route to an explicitly registered share.");

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeConnectResult.TreeId, "loopback.txt");
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeConnectResult.TreeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeConnectResult.TreeId, "loopback.txt", createResult.Status, createResult.Response);
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the routed loopback create to succeed.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeConnectResult.TreeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected the routed loopback close to succeed.");

                                TestAssertions.True(File.Exists(Path.Combine(archivePath, "loopback.txt")), "Expected the routed loopback create to persist in the selected share root.");
                                TestAssertions.False(File.Exists(Path.Combine(publicPath, "loopback.txt")), "Expected the routed loopback create to avoid sibling share roots.");
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
                        suiteId: "Interop.LoopbackSessionTree",
                        caseId: "ClientAndServerRejectImplicitLegacyShareWhenExplicitSharesAreRegistered",
                        displayName: "Client and server loopback reject the implicit legacy options share when explicit shares are registered",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropLegacyShare_" + Guid.NewGuid().ToString("N"));
                            string legacyPath = Path.Combine(rootPath, "legacy");
                            string publicPath = Path.Combine(rootPath, "public");
                            Directory.CreateDirectory(publicPath);

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
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });

                                OpenCifsServerHost server = builder.BuildHost();
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                                OpenCifsServerTreeConnectResult legacyTreeConnectResult = server.HandleTreeConnect(
                                    sessionId,
                                    client.CreateTreeConnectRequest("legacy"));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, legacyTreeConnectResult.Status, "Expected explicit share registration to suppress the implicit legacy options share.");
                                TestAssertions.Equal(0, client.ConnectedTreeIds.Length, "Expected the client to keep its tree table empty after the rejected connect.");
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


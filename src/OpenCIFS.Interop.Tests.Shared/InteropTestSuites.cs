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

    /// <summary>
    /// Shared Touchstone suites for interoperability matrix bootstrap validation.
    /// </summary>
    public static class InteropTestSuites
    {
        /// <summary>
        /// All shared interoperability test suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    InteropArtifactsSuite(),
                    LoopbackNegotiateSuite(),
                    LoopbackSessionTreeSuite(),
                    LoopbackEchoSuite(),
                    LoopbackCreditHeaderSuite(),
                    LoopbackChangeNotifySuite(),
                    LoopbackOplockSuite(),
                    LoopbackLeaseSuite(),
                    LoopbackDurableHandleSuite(),
                    LoopbackCompoundSuite(),
                    LoopbackFileIoSuite(),
                    LoopbackLockingSuite(),
                    LoopbackIoctlSuite(),
                    LoopbackMetadataSuite()
                };
            }
        }

        /// <summary>
        /// Build the interoperability bootstrap suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor InteropArtifactsSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.Bootstrap",
                displayName: "Interop bootstrap artifacts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "InteropMatrixIncludesWindowsAndSamba",
                        displayName: "Interop matrix includes Windows and Samba targets",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string interopMatrixPath = RepositoryPaths.FromRoot(Path.Combine("docs", "interop-matrix.md"));
                            FileAssertions.AssertContains(interopMatrixPath, "Windows client");
                            FileAssertions.AssertContains(interopMatrixPath, "Windows server");
                            FileAssertions.AssertContains(interopMatrixPath, "Samba client");
                            FileAssertions.AssertContains(interopMatrixPath, "Samba server");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "ReadmeDoesNotClaimImplementedDialects",
                        displayName: "Repository README stays explicit about implementation status",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string readmePath = RepositoryPaths.FromRoot("README.md");
                            FileAssertions.AssertContains(readmePath, "The verified working dialect surface is now managed direct-TCP SMB 2.0.2 and SMB 2.1; SMB 3.x and SMB1/CIFS remain backlog.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "InteropSuitesExposePositiveAndNegativeVariants",
                        displayName: "Interop shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(All, "Interop");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackNegotiateSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.Loopback",
                displayName: "Loopback negotiate coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerNegotiateSmb21",
                        displayName: "Client and server loopback negotiate SMB 2.1 with matching GUID and signing state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions());
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            if (client.NegotiatedDialect != SmbDialect.Smb21)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to select SMB 2.1.");
                            }

                            if (client.ServerGuid != server.ServerGuid)
                            {
                                throw new InvalidOperationException("Expected the client to observe the server host GUID.");
                            }

                            if (!client.IsSigningRequired)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to require signing by default.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerRespectOptionalSigningPolicy",
                        displayName: "Client and server loopback negotiate optional signing when both sides relax the policy",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                RequireSigning = false
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                RequireSigning = false
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            if (client.NegotiatedDialect != SmbDialect.Smb21)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to keep SMB 2.1 selected.");
                            }

                            if (client.IsSigningRequired)
                            {
                                throw new InvalidOperationException("Expected signing to stay optional when both sides relax the policy.");
                            }

                            if ((response.SecurityMode & Smb2SecurityMode.SigningEnabled) == 0)
                            {
                                throw new InvalidOperationException("Expected signing to remain enabled even when it is not required.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerRejectNegotiationWithoutCommonDialect",
                        displayName: "Client and server loopback reject negotiation when there is no common dialect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb311,
                                MaximumDialect = SmbDialect.Smb311
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => server.HandleNegotiate(request),
                                "Expected loopback negotiate coverage to reject client/server dialect ranges without a common SMB2 dialect.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerClampNegotiationToSmb2002WhenConfigured",
                        displayName: "Client and server loopback clamp negotiation to SMB 2.0.2 when both sides cap the dialect range",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb2002, client.NegotiatedDialect!.Value, "Expected loopback negotiation to clamp to SMB 2.0.2 when both sides cap the dialect range.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackSessionTreeSuite()
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

        /// <summary>
        /// Build the loopback SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackCreditHeaderSuite()
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

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => client.ValidateResponsePacket(parsedTamperedResponsePacket, tamperedResponseBytes),
                                "Expected the loopback client to reject tampered signed SMB2 echo responses.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback SMB2 CHANGE_NOTIFY suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackChangeNotify",
                displayName: "Loopback CHANGE_NOTIFY coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncChangeNotifyForCreate",
                        displayName: "Client and server loopback complete an async CHANGE_NOTIFY request for a created child file",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the loopback client to keep the async CHANGE_NOTIFY request pending after the interim response.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? finalResponse) && finalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response.");
                                client.ApplyResponseHeader(finalResponse!.Header);
                                FileNotifyInformation[] entries = client.ApplyChangeNotifyResult(
                                    notifyRequest,
                                    finalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload));
                                TestAssertions.Equal(1, entries.Length, "Expected the loopback CHANGE_NOTIFY completion to return a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected the created child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child.txt", entries[0].FileName, "Expected the created child file name to remain relative to the watched directory.");
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected the final async CHANGE_NOTIFY response to complete the pending client request.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncWatchTreeChangeNotifyForNestedCreate",
                        displayName: "Client and server loopback complete a watched-tree async CHANGE_NOTIFY request for a nested child file",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: true,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\nested\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\nested\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? finalResponse) && finalResponse != null, "Expected the server to emit a watched-tree final async CHANGE_NOTIFY response.");
                                client.ApplyResponseHeader(finalResponse!.Header);
                                FileNotifyInformation[] entries = client.ApplyChangeNotifyResult(
                                    notifyRequest,
                                    finalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload));
                                TestAssertions.Equal(1, entries.Length, "Expected the watched-tree CHANGE_NOTIFY completion to return a single nested notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, entries[0].Action, "Expected the nested child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("nested\\child.txt", entries[0].FileName, "Expected the watched-tree child path to remain relative to the watched directory.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCompleteAsyncChangeNotifyForRenameAndDelete",
                        displayName: "Client and server loopback complete async CHANGE_NOTIFY requests for same-directory rename and delete",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header fileOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest fileOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched\\sample.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(fileOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(sessionId, treeId, fileOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileOpenHeader, fileOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched\\sample.txt", fileOpenResult.Status, fileOpenResult.Response);

                                Smb2Header renameNotifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest renameNotifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse renameInterimResponse = server.HandleChangeNotify(renameNotifyHeader, renameNotifyRequest);
                                client.ApplyResponseHeader(renameInterimResponse.Header);

                                Smb2Header renameHeader = client.CreateRequestHeader(Smb2Command.SetInfo, treeId, sessionId: sessionId);
                                Smb2SetInfoRequest renameRequest = client.CreateSetRenameInfoRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    "watched\\renamed.txt");
                                server.ValidateAndAcceptRequestHeader(renameHeader, Smb2Command.SetInfo, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = server.HandleSetInfo(sessionId, treeId, renameRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(renameHeader, renameResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplySetRenameInfoResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, renameResult.Status, renameResult.Response, "watched\\renamed.txt");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? renameFinalResponse) && renameFinalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response for the rename.");
                                client.ApplyResponseHeader(renameFinalResponse!.Header);
                                FileNotifyInformation[] renameEntries = client.ApplyChangeNotifyResult(
                                    renameNotifyRequest,
                                    renameFinalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(renameFinalResponse.Payload));
                                TestAssertions.Equal(2, renameEntries.Length, "Expected the rename CHANGE_NOTIFY completion to return old and new name entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename notify entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename notify entry to retain the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename notify entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename notify entry to retain the renamed relative file name.");

                                Smb2Header deleteNotifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest deleteNotifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse deleteInterimResponse = server.HandleChangeNotify(deleteNotifyHeader, deleteNotifyRequest);
                                client.ApplyResponseHeader(deleteInterimResponse.Header);

                                Smb2Header dispositionHeader = client.CreateRequestHeader(Smb2Command.SetInfo, treeId, sessionId: sessionId);
                                Smb2SetInfoRequest dispositionRequest = client.CreateSetDispositionInfoRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    deletePending: true);
                                server.ValidateAndAcceptRequestHeader(dispositionHeader, Smb2Command.SetInfo, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = server.HandleSetInfo(sessionId, treeId, dispositionRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(dispositionHeader, dispositionResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplySetDispositionInfoResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, dispositionResult.Status, dispositionResult.Response, deletePending: true);

                                Smb2Header fileCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest fileCloseRequest = client.CreateCloseRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(fileCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(sessionId, treeId, fileCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileCloseHeader, fileCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? deleteFinalResponse) && deleteFinalResponse != null, "Expected the server to emit a final async CHANGE_NOTIFY response for the delete.");
                                client.ApplyResponseHeader(deleteFinalResponse!.Header);
                                FileNotifyInformation[] deleteEntries = client.ApplyChangeNotifyResult(
                                    deleteNotifyRequest,
                                    deleteFinalResponse.Header.Status,
                                    Smb2ChangeNotifyResponse.ReadFrom(deleteFinalResponse.Payload));
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected the delete CHANGE_NOTIFY completion to return a single remove entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected the delete notify entry to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected the delete notify entry to retain the renamed relative file name.");

                                Smb2Header directoryCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest directoryCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(directoryCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(sessionId, treeId, directoryCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryCloseHeader, directoryCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerCancelAsyncChangeNotifyRequest",
                        displayName: "Client and server loopback cancel an async CHANGE_NOTIFY request",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected loopback async cancel handling to cancel the pending CHANGE_NOTIFY request.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected the cancelled loopback CHANGE_NOTIFY request to leave no pending client request state.");

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerKeepChangeNotifyPendingForNonMatchingFiltersUntilCancel",
                        displayName: "Client and server loopback keep CHANGE_NOTIFY pending for non-matching filters until cancel",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header fileOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest fileOpenRequest = client.CreateCreateRequest(treeId, "watched\\sample.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(fileOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(sessionId, treeId, fileOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileOpenHeader, fileOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched\\sample.txt", fileOpenResult.Status, fileOpenResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the loopback CHANGE_NOTIFY request to remain pending after the interim response.");

                                Smb2Header writeHeader = client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: sessionId);
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, new byte[] { 0x41, 0x42 }, 0);
                                server.ValidateAndAcceptRequestHeader(writeHeader, Smb2Command.Write, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(sessionId, treeId, writeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(writeHeader, writeResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyWriteResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, writeResult.Status, writeResult.Response);

                                TestAssertions.False(server.TryDequeueAsyncResponse(out _), "Expected a filename-only CHANGE_NOTIFY request to remain pending after a size-only write mutation.");
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the non-matching change to leave the loopback CHANGE_NOTIFY request pending.");

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected the loopback non-matching CHANGE_NOTIFY request to be cancellable.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected cancelling the non-matching loopback CHANGE_NOTIFY request to clear pending client state.");

                                Smb2Header fileCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest fileCloseRequest = client.CreateCloseRequest(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(fileCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(sessionId, treeId, fileCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(fileCloseHeader, fileCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedFileOpen.PersistentFileId, watchedFileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                Smb2Header watchedCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest watchedCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watchedCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watchedCloseResult = server.HandleClose(sessionId, treeId, watchedCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(watchedCloseHeader, watchedCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, watchedCloseResult.Status, watchedCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerKeepNonRecursiveChangeNotifyPendingForNestedCreateUntilCancel",
                        displayName: "Client and server loopback keep a non-recursive CHANGE_NOTIFY pending for nested creates until cancel",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched", "nested"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 5);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header directoryOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "watched",
                                    desiredAccess: 0x80000000U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory);
                                server.ValidateAndAcceptRequestHeader(directoryOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(sessionId, treeId, directoryOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryOpenHeader, directoryOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedDirectoryOpen = client.ApplyCreateResult(treeId, "watched", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedDirectoryOpen.PersistentFileId,
                                    watchedDirectoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 256);
                                OpenCifsServerAsyncResponse interimResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);
                                client.ApplyResponseHeader(interimResponse.Header);
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the non-recursive CHANGE_NOTIFY request to remain pending after the interim response.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "watched\\nested\\child.txt", createDisposition: Smb2CreateDisposition.Create);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState childOpen = client.ApplyCreateResult(treeId, "watched\\nested\\child.txt", createResult.Status, createResult.Response);

                                TestAssertions.False(server.TryDequeueAsyncResponse(out _), "Expected a non-recursive CHANGE_NOTIFY request to remain pending for nested creates.");
                                TestAssertions.Equal(1, client.PendingRequestCount, "Expected the nested create to leave the non-recursive CHANGE_NOTIFY request pending.");

                                Smb2Header childCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest childCloseRequest = client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(childCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(sessionId, treeId, childCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(childCloseHeader, childCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2Header cancelHeader = client.CreateCancelRequestHeader(notifyHeader.MessageId);
                                OpenCifsServerCancelResult cancelResult = server.HandleCancel(cancelHeader, client.CreateCancelRequest());
                                TestAssertions.True(cancelResult.WasCancelled, "Expected the pending non-recursive CHANGE_NOTIFY request to be cancellable.");
                                client.ApplyResponseHeader(cancelResult.TargetResponseHeader!);
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected cancelling the non-recursive CHANGE_NOTIFY request to clear pending client state.");

                                Smb2Header directoryCloseHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest directoryCloseRequest = client.CreateCloseRequest(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(directoryCloseHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(sessionId, treeId, directoryCloseRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(directoryCloseHeader, directoryCloseResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(watchedDirectoryOpen.PersistentFileId, watchedDirectoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
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
                        suiteId: "Interop.LoopbackChangeNotify",
                        caseId: "ClientAndServerRejectChangeNotifyOnNonDirectoryOpen",
                        displayName: "Client and server loopback reject CHANGE_NOTIFY on a non-directory open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "watched.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 3);
                                ulong sessionId = client.SessionId!.Value;

                                Smb2Header openHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest openRequest = client.CreateCreateRequest(treeId, "watched.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(openHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = server.HandleCreate(sessionId, treeId, openRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openHeader, openResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState watchedFileOpen = client.ApplyCreateResult(treeId, "watched.txt", openResult.Status, openResult.Response);

                                Smb2Header notifyHeader = client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: sessionId);
                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    watchedFileOpen.PersistentFileId,
                                    watchedFileOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    outputBufferLength: 128);
                                OpenCifsServerAsyncResponse finalResponse = server.HandleChangeNotify(notifyHeader, notifyRequest);

                                client.ApplyResponseHeader(finalResponse.Header);
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyChangeNotifyResult(notifyRequest, finalResponse.Header.Status, Smb2ChangeNotifyResponse.ReadFrom(finalResponse.Payload)),
                                    "Expected loopback CHANGE_NOTIFY coverage to reject file opens that are not directories.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback oplock suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackOplock",
                displayName: "Loopback oplock-break coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackOplock",
                        caseId: "ClientAndServerCompleteSignedExclusiveOplockBreakFlow",
                        displayName: "Client and server loopback complete a signed exclusive oplock-break flow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession watcherClient = CreateClient();
                                OpenCifsClientSession actorClient = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint watcherTreeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, watcherClient, credential, creditRequest: 5);
                                uint actorTreeId = AuthenticateLoopbackSessionAndTree(server, actorClient, credential);
                                ulong watcherSessionId = watcherClient.SessionId!.Value;
                                ulong actorSessionId = actorClient.SessionId!.Value;

                                Smb2Header firstOpenHeader = watcherClient.CreateRequestHeader(Smb2Command.Create, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CreateRequest firstOpenRequest = watcherClient.CreateCreateRequest(
                                    watcherTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(watcherSessionId, watcherTreeId, firstOpenRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                OpenState watcherOpen = watcherClient.ApplyCreateResult(watcherTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, watcherOpen.OplockLevel, "Expected the first loopback open to receive an exclusive oplock.");

                                Smb2CreateRequest secondOpenRequest = actorClient.CreateCreateRequest(
                                    actorTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(actorSessionId, actorTreeId, secondOpenRequest);
                                OpenState actorOpen = actorClient.ApplyCreateResult(actorTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second loopback open not to receive an oplock grant.");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue an oplock-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = server.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                watcherClient.ValidateOplockBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);
                                Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                (OpenState appliedOpenState, Smb2OplockLevel previousOplockLevel, Smb2OplockLevel newOplockLevel, bool requiresAcknowledgment) =
                                    watcherClient.ApplyOplockBreakNotification(watcherTreeId, notification);
                                TestAssertions.Equal(watcherOpen.PersistentFileId, appliedOpenState.PersistentFileId, "Expected the loopback oplock-break notification to target the original open.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, previousOplockLevel, "Expected the loopback oplock-break flow to preserve the previous exclusive oplock.");
                                TestAssertions.Equal(Smb2OplockLevel.None, newOplockLevel, "Expected the loopback oplock-break flow to lower the oplock to none.");
                                TestAssertions.True(requiresAcknowledgment, "Expected exclusive loopback oplock breaks to require acknowledgment.");

                                Smb2OplockBreakAcknowledgment acknowledgment = watcherClient.CreateOplockBreakAcknowledgmentRequest(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    Smb2OplockLevel.None);
                                Smb2Header acknowledgmentHeader = watcherClient.CreateRequestHeader(Smb2Command.OplockBreak, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CompoundPacket acknowledgmentPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(acknowledgmentHeader, acknowledgment.ToByteArray())
                                });
                                byte[] acknowledgmentPacketBytes = watcherClient.FinalizeRequestPacket(acknowledgmentPacket);
                                Smb2CompoundPacket parsedAcknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                server.ValidateRequestPacket(parsedAcknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = server.HandleCompoundRequestPacket(parsedAcknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = server.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                watcherClient.ValidateResponsePacket(parsedAcknowledgmentResponsePacket, acknowledgmentResponseBytes);
                                watcherClient.ApplyResponseHeader(parsedAcknowledgmentResponsePacket.Entries[0].Header);
                                watcherClient.ApplyOplockBreakAcknowledgmentResult(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    parsedAcknowledgmentResponsePacket.Entries[0].Header.Status,
                                    Smb2OplockBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload));
                                TestAssertions.Equal(Smb2OplockLevel.None, watcherOpen.OplockLevel, "Expected the loopback oplock-break acknowledgment to preserve the lowered oplock state.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> actorCloseResult = server.HandleClose(
                                    actorSessionId,
                                    actorTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = actorOpen.PersistentFileId,
                                        VolatileFileId = actorOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, actorCloseResult.Status, "Expected the actor loopback open to close cleanly after the oplock-break flow.");

                                Smb2Header watcherCloseHeader = watcherClient.CreateRequestHeader(Smb2Command.Close, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CloseRequest watcherCloseRequest = watcherClient.CreateCloseRequest(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watcherCloseHeader, Smb2Command.Close, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watcherCloseResult = server.HandleClose(watcherSessionId, watcherTreeId, watcherCloseRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(watcherCloseHeader, watcherCloseResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                watcherClient.ApplyCloseResult(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId, watcherCloseResult.Status, watcherCloseResult.Response);
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
                        suiteId: "Interop.LoopbackOplock",
                        caseId: "ClientAndServerRejectExclusiveOplockWhenFileAlreadyHasOpen",
                        displayName: "Client and server loopback reject an exclusive oplock when the file already has an open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession firstClient = CreateClient();
                                OpenCifsClientSession secondClient = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, firstClient, credential, creditRequest: 4);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(server, secondClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2Header firstOpenHeader = firstClient.CreateRequestHeader(Smb2Command.Create, firstTreeId, sessionId: firstSessionId);
                                Smb2CreateRequest firstOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: firstSessionId, expectedTreeId: firstTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                firstClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: firstSessionId, treeId: firstTreeId));
                                OpenState firstOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, firstOpen.OplockLevel, "Expected the first loopback open without an oplock request not to receive an oplock grant.");

                                Smb2CreateRequest secondOpenRequest = secondClient.CreateCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(secondSessionId, secondTreeId, secondOpenRequest);
                                OpenState secondOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.OplockLevel, "Expected the second loopback open not to receive an exclusive oplock while the file already has an open.");
                                TestAssertions.False(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? _), "Expected loopback oplock coverage not to queue an unsolicited break when no oplock was granted.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondCloseResult = server.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = secondOpen.PersistentFileId,
                                        VolatileFileId = secondOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondCloseResult.Status, "Expected the second loopback open to close cleanly after the rejected oplock grant.");

                                Smb2Header firstCloseHeader = firstClient.CreateRequestHeader(Smb2Command.Close, firstTreeId, sessionId: firstSessionId);
                                Smb2CloseRequest firstCloseRequest = firstClient.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(firstCloseHeader, Smb2Command.Close, expectedSessionId: firstSessionId, expectedTreeId: firstTreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> firstCloseResult = server.HandleClose(firstSessionId, firstTreeId, firstCloseRequest);
                                firstClient.ApplyResponseHeader(server.CreateResponseHeader(firstCloseHeader, firstCloseResult.Status, sessionId: firstSessionId, treeId: firstTreeId));
                                firstClient.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstCloseResult.Status, firstCloseResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackLease",
                displayName: "Loopback SMB 2.1 lease coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackLease",
                        caseId: "ClientAndServerCompleteSignedLeaseBreakFlow",
                        displayName: "Client and server loopback complete a signed lease-break flow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession watcherClient = CreateClient();
                                OpenCifsClientSession actorClient = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint watcherTreeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, watcherClient, credential, creditRequest: 5);
                                uint actorTreeId = AuthenticateLoopbackSessionAndTree(server, actorClient, credential);
                                ulong watcherSessionId = watcherClient.SessionId!.Value;
                                ulong actorSessionId = actorClient.SessionId!.Value;
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 1);
                                }

                                Smb2Header firstOpenHeader = watcherClient.CreateRequestHeader(Smb2Command.Create, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CreateRequest firstOpenRequest = watcherClient.CreateCreateRequest(
                                    watcherTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    leaseKey: leaseKey);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(watcherSessionId, watcherTreeId, firstOpenRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                OpenState watcherOpen = watcherClient.ApplyCreateResult(watcherTreeId, "shared.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Lease, watcherOpen.OplockLevel, "Expected the first loopback open to receive an SMB 2.1 lease.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, watcherOpen.LeaseState, "Expected the first loopback open to receive a full read-write-handle lease.");

                                Smb2CreateRequest secondOpenRequest = actorClient.CreateCreateRequest(
                                    actorTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(actorSessionId, actorTreeId, secondOpenRequest);
                                OpenState actorOpen = actorClient.ApplyCreateResult(actorTreeId, "shared.txt", secondOpenResult.Status, secondOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second loopback open not to receive a lease grant.");

                                TestAssertions.True(server.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue a lease-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = server.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                watcherClient.ValidateLeaseBreakNotificationPacket(parsedNotificationPacket, notificationPacketBytes);
                                Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                (OpenState appliedOpenState, Smb2LeaseState previousLeaseState, Smb2LeaseState newLeaseState, bool requiresAcknowledgment) =
                                    watcherClient.ApplyLeaseBreakNotification(watcherTreeId, notification);
                                TestAssertions.Equal(watcherOpen.PersistentFileId, appliedOpenState.PersistentFileId, "Expected the loopback lease-break notification to target the original open.");
                                TestAssertions.Equal(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching, previousLeaseState, "Expected the loopback lease-break flow to preserve the previous read-write-handle lease.");
                                TestAssertions.Equal(Smb2LeaseState.None, newLeaseState, "Expected the loopback lease-break flow to lower the lease state to none.");
                                TestAssertions.True(requiresAcknowledgment, "Expected loopback lease breaks to require acknowledgment.");

                                Smb2LeaseBreakAcknowledgment acknowledgment = watcherClient.CreateLeaseBreakAcknowledgmentRequest(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId);
                                Smb2Header acknowledgmentHeader = watcherClient.CreateRequestHeader(Smb2Command.OplockBreak, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CompoundPacket acknowledgmentPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(acknowledgmentHeader, acknowledgment.ToByteArray())
                                });
                                byte[] acknowledgmentPacketBytes = watcherClient.FinalizeRequestPacket(acknowledgmentPacket);
                                Smb2CompoundPacket parsedAcknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                server.ValidateRequestPacket(parsedAcknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = server.HandleCompoundRequestPacket(parsedAcknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = server.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                watcherClient.ValidateResponsePacket(parsedAcknowledgmentResponsePacket, acknowledgmentResponseBytes);
                                watcherClient.ApplyResponseHeader(parsedAcknowledgmentResponsePacket.Entries[0].Header);
                                watcherClient.ApplyLeaseBreakAcknowledgmentResult(
                                    watcherOpen.PersistentFileId,
                                    watcherOpen.VolatileFileId,
                                    parsedAcknowledgmentResponsePacket.Entries[0].Header.Status,
                                    Smb2LeaseBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload));
                                TestAssertions.Equal(Smb2LeaseState.None, watcherOpen.LeaseState, "Expected the loopback lease-break acknowledgment to preserve the lowered lease state.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> actorCloseResult = server.HandleClose(
                                    actorSessionId,
                                    actorTreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = actorOpen.PersistentFileId,
                                        VolatileFileId = actorOpen.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, actorCloseResult.Status, "Expected the actor loopback open to close cleanly after the lease-break flow.");

                                Smb2Header watcherCloseHeader = watcherClient.CreateRequestHeader(Smb2Command.Close, watcherTreeId, sessionId: watcherSessionId);
                                Smb2CloseRequest watcherCloseRequest = watcherClient.CreateCloseRequest(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(watcherCloseHeader, Smb2Command.Close, expectedSessionId: watcherSessionId, expectedTreeId: watcherTreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> watcherCloseResult = server.HandleClose(watcherSessionId, watcherTreeId, watcherCloseRequest);
                                watcherClient.ApplyResponseHeader(server.CreateResponseHeader(watcherCloseHeader, watcherCloseResult.Status, sessionId: watcherSessionId, treeId: watcherTreeId));
                                watcherClient.ApplyCloseResult(watcherOpen.PersistentFileId, watcherOpen.VolatileFileId, watcherCloseResult.Status, watcherCloseResult.Response);
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
                        suiteId: "Interop.LoopbackLease",
                        caseId: "ClientAndServerRejectSameLeaseKeyOnDifferentPath",
                        displayName: "Client and server loopback reject the same lease key on a different path",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "first.txt"), "first");
                            File.WriteAllText(Path.Combine(sharePath, "other.txt"), "other");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId!.Value;
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 21);
                                }

                                Smb2Header firstOpenHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: sessionId);
                                Smb2CreateRequest firstOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "first.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                    leaseKey: leaseKey);
                                server.ValidateAndAcceptRequestHeader(firstOpenHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpenResult = server.HandleCreate(sessionId, treeId, firstOpenRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(firstOpenHeader, firstOpenResult.Status, sessionId: sessionId, treeId: treeId));
                                OpenState firstOpen = client.ApplyCreateResult(treeId, "first.txt", firstOpenResult.Status, firstOpenResult.Response);
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.OplockLevel, "Expected the initial loopback lease-backed open to succeed.");

                                Smb2CreateRequest secondOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "other.txt",
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: Smb2LeaseState.ReadCaching,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpenResult = server.HandleCreate(sessionId, treeId, secondOpenRequest);
                                TestAssertions.Equal(NtStatus.InvalidParameter, secondOpenResult.Status, "Expected the same lease key on a different path to be rejected.");

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: sessionId);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(sessionId, treeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: sessionId, treeId: treeId));
                                client.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, closeResult.Status, closeResult.Response);
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback durable-handle reconnect suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackDurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackDurable",
                displayName: "Loopback durable-handle reconnect coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerReconnectDurableBatchOpenAcrossHosts",
                        displayName: "Client and server loopback reconnect a durable batch open across hosts that share server state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial loopback open to be granted durable reconnect state.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, durableOpen.OplockLevel, "Expected the initial loopback durable open to receive a batch oplock.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, reconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", reconnectResult.Status, reconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected loopback open to stay durable.");
                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectedOpen.VolatileFileId == durableOpen.VolatileFileId, "Expected durable reconnect to allocate a fresh volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectedOpen.OplockLevel, "Expected durable reconnect to preserve the granted batch oplock.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateReadRequest(
                                        reconnectedOpen.PersistentFileId,
                                        reconnectedOpen.VolatileFileId,
                                        length: 32,
                                        offset: 0,
                                        minimumCount: 1));
                                byte[] buffer = secondClient.ApplyReadResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    readResult.Status,
                                    readResult.Response);
                                TestAssertions.Equal("durable-data", Encoding.UTF8.GetString(buffer), "Expected the reconnected durable open to preserve file access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                                TestAssertions.Equal(0, secondClient.OpenCount, "Expected the loopback durable reconnect flow to leave no tracked opens after close.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerRejectMismatchedDurableReconnectAndPreserveDetachedOpen",
                        displayName: "Client and server loopback reject mismatched durable reconnect requests and preserve the detached open for the correct retry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest invalidReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "wrong.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, invalidReconnectRequest);
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidReconnectResult.Status, "Expected the loopback durable reconnect flow to reject the wrong path.");

                                Smb2CreateRequest validReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, validReconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", validReconnectResult.Status, validReconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the detached durable open to remain reconnectable after a mismatched retry.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerPreserveDurableByteRangeLocksAcrossReconnect",
                        displayName: "Client and server loopback preserve durable byte-range locks across reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> initialLockResult = firstHost.HandleLock(
                                    firstSessionId,
                                    firstTreeId,
                                    firstClient.CreateLockRequest(
                                        durableOpen.PersistentFileId,
                                        durableOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                firstClient.ApplyLockResult(durableOpen.PersistentFileId, durableOpen.VolatileFileId, initialLockResult.Status, initialLockResult.Response);

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                OpenCifsServerOperationResult<Smb2CreateResponse> competingOpenResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCreateRequest(
                                        secondTreeId,
                                        "shared.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState competingOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", competingOpenResult.Status, competingOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> detachedReadConflict = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateReadRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        length: 4,
                                        offset: 0,
                                        minimumCount: 1));
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadConflict.Status, "Expected detached durable locks to block overlapping loopback reads.");

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, reconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", reconnectResult.Status, reconnectResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> reconnectedLockConflict = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockConflict.Status, "Expected the reconnected durable open to restore its byte-range lock ownership.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        reconnectedOpen.PersistentFileId,
                                        reconnectedOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }));
                                secondClient.ApplyLockResult(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId, unlockResult.Status, unlockResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> postUnlockLockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                secondClient.ApplyLockResult(competingOpen.PersistentFileId, competingOpen.VolatileFileId, postUnlockLockResult.Status, postUnlockLockResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> competingCloseResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(competingOpen.PersistentFileId, competingOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(competingOpen.PersistentFileId, competingOpen.VolatileFileId, competingCloseResult.Status, competingCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> durableCloseResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId, durableCloseResult.Status, durableCloseResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackEchoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackEcho",
                displayName: "Loopback echo coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackEcho",
                        caseId: "ClientAndServerCompleteAuthenticatedEchoWithHeaders",
                        displayName: "Client and server loopback complete an authenticated header-wrapped SMB2 echo",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            server.ValidateAndAcceptRequestHeader(echoHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId, echoRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(echoHeader, echoResult.Status, sessionId: sessionId));
                            client.ApplyEchoResult(echoResult.Status, echoResult.Response);

                            TestAssertions.True(client.IsAuthenticated, "Expected loopback echo to preserve authenticated client state.");
                            TestAssertions.True(client.SessionId == sessionId, "Expected loopback echo to preserve the authenticated session identifier.");
                            TestAssertions.Equal(1, client.AvailableCredits, "Expected loopback echo to preserve the bounded client credit window.");
                            TestAssertions.Equal(1, server.AvailableCredits, "Expected loopback echo to preserve the bounded server credit window.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackEcho",
                        caseId: "ClientAndServerRejectEchoForUnknownSession",
                        displayName: "Client and server loopback reject echo requests for an unknown session",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            server.ValidateAndAcceptRequestHeader(echoHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId + 1, echoRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(echoHeader, echoResult.Status, sessionId: sessionId + 1));

                            TestAssertions.Throws<InvalidOperationException>(
                                () => client.ApplyEchoResult(echoResult.Status, echoResult.Response),
                                "Expected loopback echo coverage to reject unknown sessions.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback SMB2 compounding suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackCompoundSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackCompound",
                displayName: "Loopback SMB2 compounding coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerCompleteUnrelatedCompoundFileIoChain",
                        displayName: "Client and server loopback complete an unrelated compounded write, flush, read, and close chain",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 8);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "compound.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "compound.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("compound data");
                                Smb2Header writeHeader = client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: client.SessionId.Value);
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                Smb2Header flushHeader = client.CreateRequestHeader(Smb2Command.Flush, treeId, sessionId: client.SessionId.Value);
                                Smb2FlushRequest flushRequest = client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                                Smb2Header readHeader = client.CreateRequestHeader(Smb2Command.Read, treeId, sessionId: client.SessionId.Value);
                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length);
                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId.Value);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(writeHeader, writeRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(flushHeader, flushRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(readHeader, readRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                                    });
                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());

                                client.ApplyCompoundResponsePacket(parsedResponsePacket);

                                Smb2WriteResponse writeResponse = Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                                Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));
                                Smb2ReadResponse readResponse = Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[2].Header.Command, parsedResponsePacket.Entries[2].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[3].Header.Command, parsedResponsePacket.Entries[3].Payload));

                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[0].Header.Status, writeResponse), "Unexpected compounded loopback write count.");
                                client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[1].Header.Status, flushResponse);
                                byte[] readBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[2].Header.Status, readResponse);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[3].Header.Status, closeResponse);

                                TestAssertions.True(parsedResponsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response to point at a subsequent response.");
                                TestAssertions.SequenceEqual(payload, readBytes, "Unexpected bytes returned by the compounded loopback read path.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the compounded close response to clear the loopback open.");
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected every compounded loopback request to complete.");
                                TestAssertions.Equal(8, client.AvailableCredits, "Expected the loopback client to restore the negotiated credit window after the compounded response.");
                                TestAssertions.Equal(8, server.AvailableCredits, "Expected the loopback server to restore the negotiated credit window after the compounded response.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "compound.txt")), "Unexpected bytes persisted by the compounded loopback file-I/O path.");
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
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerCompleteRelatedCompoundTreeMetadataLockIoctlAndCloseChain",
                        displayName: "Client and server loopback complete a related compounded tree-connect, create, set-info, query-info, lock, IOCTL, close, and tree-disconnect chain",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropRelatedCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 9);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                                Smb2Header createHeader = client.CreateRelatedRequestHeader(Smb2Command.Create, sessionId: sessionId);
                                Smb2Header setInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.SetInfo, sessionId: sessionId);
                                Smb2Header queryInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: sessionId);
                                Smb2Header lockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header unlockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header ioctlHeader = client.CreateRelatedRequestHeader(Smb2Command.Ioctl, sessionId: sessionId);
                                Smb2Header closeHeader = client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: sessionId);
                                Smb2Header treeDisconnectHeader = client.CreateRelatedRequestHeader(Smb2Command.TreeDisconnect, sessionId: sessionId);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            treeConnectHeader,
                                            client.CreateTreeConnectRequest("public").ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            createHeader,
                                            new Smb2CreateRequest
                                            {
                                                RequestedOplockLevel = Smb2OplockLevel.None,
                                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                                DesiredAccess = 0xC0000000U,
                                                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                                ShareAccess = 0x00000007U,
                                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                                Name = "related.txt",
                                                CreateContexts = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            setInfoHeader,
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            queryInfoHeader,
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            lockHeader,
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            unlockHeader,
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.Unlock
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            ioctlHeader,
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            closeHeader,
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            treeDisconnectHeader,
                                            new Smb2TreeDisconnectRequest().ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedResponsePacket);

                                Smb2TreeConnectResponse treeConnectResponse = Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                                Smb2CreateResponse createResponse = Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));
                                Smb2SetInfoResponse setInfoResponse = Smb2SetInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[2].Header.Command, parsedResponsePacket.Entries[2].Payload));
                                Smb2QueryInfoResponse queryInfoResponse = Smb2QueryInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[3].Header.Command, parsedResponsePacket.Entries[3].Payload));
                                Smb2LockResponse lockResponse = Smb2LockResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[4].Header.Command, parsedResponsePacket.Entries[4].Payload));
                                Smb2LockResponse unlockResponse = Smb2LockResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[5].Header.Command, parsedResponsePacket.Entries[5].Payload));
                                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[6].Header.Command, parsedResponsePacket.Entries[6].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[7].Header.Command, parsedResponsePacket.Entries[7].Payload));
                                Smb2TreeDisconnectResponse treeDisconnectResponse = Smb2TreeDisconnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[8].Header.Command, parsedResponsePacket.Entries[8].Payload));

                                client.ApplyTreeConnectResult("public", parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[0].Header.Status, treeConnectResponse);
                                OpenState openState = client.ApplyCreateResult(parsedResponsePacket.Entries[0].Header.TreeId, "related.txt", parsedResponsePacket.Entries[1].Header.Status, createResponse);
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[2].Header.Status, setInfoResponse);
                                FileBasicInformation relatedBasicInformation = FileBasicInformation.ReadFrom(client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[3].Header.Status, queryInfoResponse));
                                client.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[4].Header.Status, lockResponse);
                                client.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[5].Header.Status, unlockResponse);
                                SrvSnapshotArray snapshotArray = client.ApplyEnumerateSnapshotsResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[6].Header.Status, ioctlResponse);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[7].Header.Status, closeResponse);
                                client.ApplyTreeDisconnectResult(parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[8].Header.Status, treeDisconnectResponse);

                                TestAssertions.True((relatedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected related compounded loopback FILE_BASIC_INFORMATION queries to include Hidden.");
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected related compounded loopback snapshot enumeration to expose no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected related compounded loopback snapshot enumeration to return an empty list.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations, parsedResponsePacket.Entries[1].Header.Flags, "Expected related compounded loopback responses to mark subsequent entries as related operations.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the related compounded close response to clear the loopback open.");
                                TestAssertions.Equal(0, client.ConnectedTreeIds.Length, "Expected the related compounded tree-disconnect response to clear the connected tree.");
                                TestAssertions.Equal(9, client.AvailableCredits, "Expected the related compounded loopback response to restore the negotiated client credit window.");
                                TestAssertions.Equal(9, server.AvailableCredits, "Expected the related compounded loopback response to restore the negotiated server credit window.");
                                TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "related.txt")) & System.IO.FileAttributes.Hidden) != 0, "Expected the related compounded loopback set-info request to persist the Hidden attribute.");
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
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerRejectRelatedCompoundChainsWithoutRequiredContext",
                        displayName: "Client and server loopback reject related compounded packets that begin outside the supported synchronous compound surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientCredential credential = CreateCredential();
                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession unsupportedClient = CreateClient();
                            ulong unsupportedSessionId = AuthenticateLoopbackSessionWithHeaders(server, unsupportedClient, credential, creditRequest: 4);

                            Smb2Header echoHeader = unsupportedClient.CreateRequestHeader(Smb2Command.Echo, sessionId: unsupportedSessionId);
                            Smb2Header missingTreeReadHeader = unsupportedClient.CreateRelatedRequestHeader(Smb2Command.Read, sessionId: unsupportedSessionId);
                            Smb2CompoundPacket missingTreePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        echoHeader,
                                        unsupportedClient.CreateEchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        missingTreeReadHeader,
                                        new Smb2ReadRequest
                                        {
                                            Length = 1,
                                            Offset = 0,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue,
                                            MinimumCount = 0,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            ReadChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(missingTreePacket.ToByteArray())),
                                "Expected loopback related compounded packets that begin with commands outside the supported synchronous compound surface to be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerPropagateRelatedCreateFailureAcrossMetadataLockIoctlAndCloseOperations",
                        displayName: "Client and server loopback propagate related create failures across later metadata, locking, IOCTL, and close operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropRelatedCompoundFailure_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "collision.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 7);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                                Smb2Header createHeader = client.CreateRelatedRequestHeader(Smb2Command.Create, sessionId: sessionId);
                                Smb2Header setInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.SetInfo, sessionId: sessionId);
                                Smb2Header queryInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: sessionId);
                                Smb2Header lockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header ioctlHeader = client.CreateRelatedRequestHeader(Smb2Command.Ioctl, sessionId: sessionId);
                                Smb2Header closeHeader = client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: sessionId);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            treeConnectHeader,
                                            client.CreateTreeConnectRequest("public").ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            createHeader,
                                            new Smb2CreateRequest
                                            {
                                                RequestedOplockLevel = Smb2OplockLevel.None,
                                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                                DesiredAccess = 0xC0000000U,
                                                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                                ShareAccess = 0x00000007U,
                                                CreateDisposition = Smb2CreateDisposition.Create,
                                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                                Name = "collision.txt",
                                                CreateContexts = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            setInfoHeader,
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            queryInfoHeader,
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            lockHeader,
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            ioctlHeader,
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            closeHeader,
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedResponsePacket);
                                client.ApplyTreeConnectResult("public", parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[0].Header.Status, Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload)));

                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[1].Header.Status, "Expected the loopback related create to report the collision.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[2].Header.Status, "Expected the loopback related set-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[3].Header.Status, "Expected the loopback related query-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[4].Header.Status, "Expected the loopback related lock to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[5].Header.Status, "Expected the loopback related IOCTL to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[6].Header.Status, "Expected the loopback related close to inherit the create failure status.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the failed loopback related create not to allocate an open handle.");
                                TestAssertions.Equal("seed", File.ReadAllText(Path.Combine(sharePath, "collision.txt")), "Expected the loopback propagated create failure to leave the backing file unchanged.");
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
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerRejectMixedCompoundStyles",
                        displayName: "Client and server loopback reject compounded packets that mix unrelated and related styles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 3);

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId),
                                        client.CreateEchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRelatedRequestHeader(Smb2Command.Logoff, sessionId: sessionId),
                                        client.CreateLogoffRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId),
                                        client.CreateEchoRequest().ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray())),
                                "Expected loopback compounded coverage to reject chains that mix unrelated and related styles.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback file-I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackFileIoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackFileIo",
                displayName: "Loopback file-I/O coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerCompleteFileIoLifecycle",
                        displayName: "Client and server loopback complete create, write, flush, read, and close against a temp share",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "loopback.txt");
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "loopback.txt", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the created loopback open.");

                                byte[] payload = Encoding.UTF8.GetBytes("loopback data");
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(client.SessionId!.Value, treeId, writeRequest);
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback write count.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = server.HandleFlush(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, flushResult.Status, flushResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length));
                                byte[] readBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readResult.Status, readResult.Response);
                                TestAssertions.SequenceEqual(payload, readBytes, "Unexpected loopback read payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback open after close.");

                                byte[] storedBytes = File.ReadAllBytes(Path.Combine(sharePath, "loopback.txt"));
                                TestAssertions.SequenceEqual(payload, storedBytes, "Unexpected bytes persisted by the loopback file-I/O path.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerReportEofAfterReadingPastData",
                        displayName: "Client and server loopback report EOF cleanly after reading past the written data",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "eof.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "eof.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("abc");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> eofResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 3));
                                byte[] eofBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, eofResult.Status, eofResult.Response);
                                TestAssertions.Equal(0, eofBytes.Length, "Expected loopback EOF reads to return an empty payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerDeleteDeleteOnCloseFileAndBlockReopen",
                        displayName: "Client and server loopback delete a delete-on-close file and reject reopen while it is pending",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "transient.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "transient.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("temporary");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected delete-on-close loopback write count.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> reopenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "transient.txt", createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.DeletePending, reopenResult.Status, "Expected loopback reopen to fail while the file is delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient.txt")), "Expected the delete-on-close loopback file to be removed when the last open closes.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerRejectInvalidIdentifiersAcrossFileIoSurface",
                        displayName: "Client and server loopback reject invalid session, tree, and open identifiers across the bounded file-I/O surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropInvalidIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "identifiers.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "identifiers.txt", createResult.Status, createResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateSessionResult = server.HandleCreate(
                                    client.SessionId.Value + 1,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "other.txt"));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateSessionResult.Status, "Expected loopback create requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCreateResult(treeId, "other.txt", invalidCreateSessionResult.Status, invalidCreateSessionResult.Response),
                                    "Expected the client to surface invalid-session create failures.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateTreeResult = server.HandleCreate(
                                    client.SessionId.Value,
                                    treeId + 1,
                                    client.CreateCreateRequest(treeId, "other.txt"));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateTreeResult.Status, "Expected loopback create requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCreateResult(treeId, "other.txt", invalidCreateTreeResult.Status, invalidCreateTreeResult.Response),
                                    "Expected the client to surface invalid-tree create failures.");

                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0);
                                OpenCifsServerOperationResult<Smb2ReadResponse> invalidReadSessionResult = server.HandleRead(client.SessionId.Value + 1, treeId, readRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidReadSessionResult.Status, "Expected loopback read requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, invalidReadSessionResult.Status, invalidReadSessionResult.Response),
                                    "Expected the client to surface invalid-session read failures.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> invalidReadTreeResult = server.HandleRead(client.SessionId.Value, treeId + 1, readRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidReadTreeResult.Status, "Expected loopback read requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, invalidReadTreeResult.Status, invalidReadTreeResult.Response),
                                    "Expected the client to surface invalid-tree read failures.");

                                byte[] payload = Encoding.UTF8.GetBytes("x");
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                OpenCifsServerOperationResult<Smb2WriteResponse> invalidWriteSessionResult = server.HandleWrite(client.SessionId.Value + 1, treeId, writeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidWriteSessionResult.Status, "Expected loopback write requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, invalidWriteSessionResult.Status, invalidWriteSessionResult.Response),
                                    "Expected the client to surface invalid-session write failures.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> invalidWriteTreeResult = server.HandleWrite(client.SessionId.Value, treeId + 1, writeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidWriteTreeResult.Status, "Expected loopback write requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, invalidWriteTreeResult.Status, invalidWriteTreeResult.Response),
                                    "Expected the client to surface invalid-tree write failures.");

                                Smb2FlushRequest flushRequest = client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                                OpenCifsServerOperationResult<Smb2FlushResponse> invalidFlushSessionResult = server.HandleFlush(client.SessionId.Value + 1, treeId, flushRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidFlushSessionResult.Status, "Expected loopback flush requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, invalidFlushSessionResult.Status, invalidFlushSessionResult.Response),
                                    "Expected the client to surface invalid-session flush failures.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> invalidFlushTreeResult = server.HandleFlush(client.SessionId.Value, treeId + 1, flushRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidFlushTreeResult.Status, "Expected loopback flush requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, invalidFlushTreeResult.Status, invalidFlushTreeResult.Response),
                                    "Expected the client to surface invalid-tree flush failures.");

                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> invalidCloseSessionResult = server.HandleClose(client.SessionId.Value + 1, treeId, closeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCloseSessionResult.Status, "Expected loopback close requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, invalidCloseSessionResult.Status, invalidCloseSessionResult.Response),
                                    "Expected the client to surface invalid-session close failures.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> invalidCloseTreeResult = server.HandleClose(client.SessionId.Value, treeId + 1, closeRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCloseTreeResult.Status, "Expected loopback close requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, invalidCloseTreeResult.Status, invalidCloseTreeResult.Response),
                                    "Expected the client to surface invalid-tree close failures.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(client.SessionId.Value, treeId, closeRequest);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerCreateDirectoriesThroughBoundedCreateDispositions",
                        displayName: "Client and server loopback create directories through bounded SMB2 FILE_DIRECTORY_FILE create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-directory"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createDirectoryRequest = client.CreateCreateRequest(
                                    treeId,
                                    "loopback-directory",
                                    desiredAccess: 0x80000000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Create,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createDirectoryResult = server.HandleCreate(client.SessionId!.Value, treeId, createDirectoryRequest);
                                OpenState createdDirectoryOpen = client.ApplyCreateResult(treeId, "loopback-directory", createDirectoryResult.Status, createDirectoryResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, createDirectoryResult.Response.CreateAction, "Expected loopback FILE_CREATE on a directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "loopback-directory")), "Expected the loopback create request to materialize the backing directory.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> createDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(createdDirectoryOpen.PersistentFileId, createdDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(createdDirectoryOpen.PersistentFileId, createdDirectoryOpen.VolatileFileId, createDirectoryClose.Status, createDirectoryClose.Response);

                                Smb2CreateRequest existingDirectoryOpenIfRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x80000000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.OpenIf,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> existingDirectoryOpenIfResult = server.HandleCreate(client.SessionId!.Value, treeId, existingDirectoryOpenIfRequest);
                                OpenState existingDirectoryOpen = client.ApplyCreateResult(treeId, "existing-directory", existingDirectoryOpenIfResult.Status, existingDirectoryOpenIfResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Opened, existingDirectoryOpenIfResult.Response.CreateAction, "Expected loopback FILE_OPEN_IF on an existing directory to report Opened.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> existingDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(existingDirectoryOpen.PersistentFileId, existingDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(existingDirectoryOpen.PersistentFileId, existingDirectoryOpen.VolatileFileId, existingDirectoryClose.Status, existingDirectoryClose.Response);

                                Smb2CreateRequest plainExistingDirectoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x00000080U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.None);
                                OpenCifsServerOperationResult<Smb2CreateResponse> plainExistingDirectoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, plainExistingDirectoryOpenRequest);
                                OpenState plainExistingDirectoryOpen = client.ApplyCreateResult(treeId, "existing-directory", plainExistingDirectoryOpenResult.Status, plainExistingDirectoryOpenResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Opened, plainExistingDirectoryOpenResult.Response.CreateAction, "Expected loopback plain opens of existing directories to report Opened.");
                                TestAssertions.True((plainExistingDirectoryOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected loopback plain opens of existing directories to return directory metadata.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> plainExistingDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(plainExistingDirectoryOpen.PersistentFileId, plainExistingDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(plainExistingDirectoryOpen.PersistentFileId, plainExistingDirectoryOpen.VolatileFileId, plainExistingDirectoryClose.Status, plainExistingDirectoryClose.Response);

                                Smb2CreateRequest nonDirectoryExistingDirectoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "existing-directory",
                                    desiredAccess: 0x00000080U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Normal,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.NonDirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> nonDirectoryExistingDirectoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, nonDirectoryExistingDirectoryOpenRequest);
                                TestAssertions.Equal(NtStatus.FileIsADirectory, nonDirectoryExistingDirectoryOpenResult.Status, "Expected loopback explicit FILE_NON_DIRECTORY_FILE opens against an existing directory to remain rejected.");

                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear directory opens after the bounded loopback directory-create slice closes them.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerOverwriteAndSupersedeFiles",
                        displayName: "Client and server loopback overwrite and supersede files through bounded SMB2 create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> seedOverwriteCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "overwrite-target.txt"));
                                OpenState seedOverwriteOpen = client.ApplyCreateResult(treeId, "overwrite-target.txt", seedOverwriteCreate.Status, seedOverwriteCreate.Response);
                                byte[] overwritePayload = Encoding.UTF8.GetBytes("seed overwrite");
                                OpenCifsServerOperationResult<Smb2WriteResponse> seedOverwriteWrite = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, overwritePayload, 0));
                                client.ApplyWriteResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteWrite.Status, seedOverwriteWrite.Response);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seedOverwriteAllocation = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, 64));
                                client.ApplySetInfoResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteAllocation.Status, seedOverwriteAllocation.Response);
                                OpenCifsServerOperationResult<Smb2CloseResponse> seedOverwriteClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId));
                                client.ApplyCloseResult(seedOverwriteOpen.PersistentFileId, seedOverwriteOpen.VolatileFileId, seedOverwriteClose.Status, seedOverwriteClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-target.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf));
                                OpenState overwrittenOpen = client.ApplyCreateResult(treeId, "overwrite-target.txt", overwriteIfResult.Status, overwriteIfResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, overwriteIfResult.Response.CreateAction, "Expected loopback FILE_OVERWRITE_IF on an existing file to report Overwritten.");
                                TestAssertions.Equal(0UL, overwriteIfResult.Response.EndOfFile, "Expected loopback FILE_OVERWRITE_IF to truncate the existing file.");
                                TestAssertions.Equal(0UL, overwriteIfResult.Response.AllocationSize, "Expected loopback FILE_OVERWRITE_IF to reset declared allocation state after truncation.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwrittenClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId));
                                client.ApplyCloseResult(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId, overwrittenClose.Status, overwrittenClose.Response);
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "overwrite-target.txt")).Length, "Expected loopback FILE_OVERWRITE_IF to leave the backing file truncated.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfCreatedResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-created.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf));
                                OpenState overwriteIfCreatedOpen = client.ApplyCreateResult(treeId, "overwrite-created.txt", overwriteIfCreatedResult.Status, overwriteIfCreatedResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, overwriteIfCreatedResult.Response.CreateAction, "Expected loopback FILE_OVERWRITE_IF on a missing file to report Created.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteIfCreatedClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(overwriteIfCreatedOpen.PersistentFileId, overwriteIfCreatedOpen.VolatileFileId));
                                client.ApplyCloseResult(overwriteIfCreatedOpen.PersistentFileId, overwriteIfCreatedOpen.VolatileFileId, overwriteIfCreatedClose.Status, overwriteIfCreatedClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> seedSupersedeCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "supersede-target.txt"));
                                OpenState seedSupersedeOpen = client.ApplyCreateResult(treeId, "supersede-target.txt", seedSupersedeCreate.Status, seedSupersedeCreate.Response);
                                byte[] supersedePayload = Encoding.UTF8.GetBytes("seed supersede");
                                OpenCifsServerOperationResult<Smb2WriteResponse> seedSupersedeWrite = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, supersedePayload, 0));
                                client.ApplyWriteResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeWrite.Status, seedSupersedeWrite.Response);
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seedSupersedeAllocation = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, 96));
                                client.ApplySetInfoResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeAllocation.Status, seedSupersedeAllocation.Response);
                                OpenCifsServerOperationResult<Smb2CloseResponse> seedSupersedeClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId));
                                client.ApplyCloseResult(seedSupersedeOpen.PersistentFileId, seedSupersedeOpen.VolatileFileId, seedSupersedeClose.Status, seedSupersedeClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> supersedeResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "supersede-target.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Supersede));
                                OpenState supersededOpen = client.ApplyCreateResult(treeId, "supersede-target.txt", supersedeResult.Status, supersedeResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Superseded, supersedeResult.Response.CreateAction, "Expected loopback FILE_SUPERSEDE on an existing file to report Superseded.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.EndOfFile, "Expected loopback FILE_SUPERSEDE to replace the file with an empty one.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.AllocationSize, "Expected loopback FILE_SUPERSEDE to reset declared allocation state after replacement.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> supersedeClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId));
                                client.ApplyCloseResult(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId, supersedeClose.Status, supersedeClose.Response);
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "supersede-target.txt")).Length, "Expected loopback FILE_SUPERSEDE to leave the backing file truncated.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback overwrite and supersede slice to close all tracked opens.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerApplyCreateTimeFileAttributesAndRejectReadOnlyDeleteOnCloseCreates",
                        displayName: "Client and server loopback apply bounded create-time file attributes and reject read-only delete-on-close creates",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite-hidden.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "created-hidden.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                OpenState hiddenCreateOpen = client.ApplyCreateResult(treeId, "created-hidden.txt", hiddenCreateResult.Status, hiddenCreateResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Created, hiddenCreateResult.Response.CreateAction, "Expected loopback hidden create to report Created.");
                                TestAssertions.True(
                                    (hiddenCreateResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected loopback hidden create to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "created-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the loopback hidden create to apply the Hidden attribute to the backing file.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenCreateClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(hiddenCreateOpen.PersistentFileId, hiddenCreateOpen.VolatileFileId));
                                client.ApplyCloseResult(hiddenCreateOpen.PersistentFileId, hiddenCreateOpen.VolatileFileId, hiddenCreateClose.Status, hiddenCreateClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenOverwriteResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "overwrite-hidden.txt",
                                        desiredAccess: 0xC0000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.OverwriteIf,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                OpenState hiddenOverwriteOpen = client.ApplyCreateResult(treeId, "overwrite-hidden.txt", hiddenOverwriteResult.Status, hiddenOverwriteResult.Response);
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, hiddenOverwriteResult.Response.CreateAction, "Expected loopback hidden overwrite-if on an existing file to report Overwritten.");
                                TestAssertions.True(
                                    (hiddenOverwriteResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected loopback hidden overwrite-if to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "overwrite-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the loopback hidden overwrite-if to apply the Hidden attribute to the backing file.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenOverwriteClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(hiddenOverwriteOpen.PersistentFileId, hiddenOverwriteOpen.VolatileFileId));
                                client.ApplyCloseResult(hiddenOverwriteOpen.PersistentFileId, hiddenOverwriteOpen.VolatileFileId, hiddenOverwriteClose.Status, hiddenOverwriteClose.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDeleteOnCloseCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "transient-readonly.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDeleteOnCloseCreate.Status, "Expected loopback read-only FILE_DELETE_ON_CLOSE on a new file to fail with STATUS_CANNOT_DELETE.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient-readonly.txt")), "Expected loopback read-only delete-on-close create failures not to materialize a backing file.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback create-attribute slice to close all tracked opens.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerRejectReadOnlyDeleteOnCloseForExistingAndDirectoryTargets",
                        displayName: "Client and server loopback reject read-only delete-on-close requests for existing files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-file.txt",
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileOpen.Status, "Expected loopback existing read-only files to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the loopback existing read-only file to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryOpen.Status, "Expected loopback existing read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the loopback existing read-only directory to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryCreate = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-created-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory | OpenCIFS.Protocol.FileAttributes.ReadOnly,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Create,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryCreate.Status, "Expected loopback new read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "readonly-created-directory")), "Expected failed loopback read-only directory creates not to materialize a backing directory.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback read-only delete-on-close failure slice not to create tracked opens.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerDeleteEmptyDirectoryAndBlockChildCreatesWhilePending",
                        displayName: "Client and server loopback delete an empty directory on last close and block child creates while it is pending",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "transient-directory"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "transient-directory",
                                    desiredAccess: 0x80010000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, directoryOpenRequest);
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "transient-directory", directoryOpenResult.Status, directoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> childCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "transient-directory/child.txt", createDisposition: Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, childCreateResult.Status, "Expected loopback child creates beneath a delete-pending directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "transient-directory")), "Expected the loopback empty directory to be removed when the last delete-pending open closes.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the delete-pending directory open after close.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback metadata suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackMetadataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackMetadata",
                displayName: "Loopback metadata coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerAllowAttributeOnlyReopenWhileStillRejectingDataReadAcrossShareNone",
                        displayName: "Client and server loopback allow attribute-only reopen across share-none while still rejecting data-read reopens",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> exclusiveOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x00120196U,
                                        shareAccess: 0x00000000U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState exclusiveOpen = client.ApplyCreateResult(treeId, "notes.txt", exclusiveOpenResult.Status, exclusiveOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState attributeOnlyOpen = client.ApplyCreateResult(treeId, "notes.txt", attributeOnlyOpenResult.Status, attributeOnlyOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, FileInformationClass.InternalInformation));
                                FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, internalInformationQueryResult.Status, internalInformationQueryResult.Response));
                                TestAssertions.Equal(attributeOnlyOpen.PersistentFileId, internalInformation.IndexNumber, "Unexpected loopback FILE_INTERNAL_INFORMATION index number for the metadata-only reopen.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dataReadOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.SharingViolation, dataReadOpenResult.Status, "Expected loopback data-read reopens to remain blocked across a share-none open.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId));
                                client.ApplyCloseResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, attributeOnlyCloseResult.Status, attributeOnlyCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> exclusiveCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(exclusiveOpen.PersistentFileId, exclusiveOpen.VolatileFileId));
                                client.ApplyCloseResult(exclusiveOpen.PersistentFileId, exclusiveOpen.VolatileFileId, exclusiveCloseResult.Status, exclusiveCloseResult.Response);
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
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerCompleteMetadataLifecycle",
                        displayName: "Client and server loopback complete bounded query-info and set-info metadata operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "notes.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "notes.txt", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the loopback metadata open.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> allocationResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 64));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, allocationResult.Status, allocationResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("hello world");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback metadata write count.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> endOfFileResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetEndOfFileInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 12));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, endOfFileResult.Status, endOfFileResult.Response);

                                ulong creationTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 8, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastAccessTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 9, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastWriteTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 10, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> basicResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = creationTime,
                                            LastAccessTime = lastAccessTime,
                                            LastWriteTime = lastWriteTime,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, basicResult.Status, basicResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, standardResult.Status, standardResult.Response));
                                TestAssertions.Equal(64UL, standardInformation.AllocationSize, "Unexpected loopback FILE_STANDARD_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, standardInformation.EndOfFile, "Unexpected loopback FILE_STANDARD_INFORMATION EOF size.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, basicQueryResult.Status, basicQueryResult.Response));
                                TestAssertions.Equal(creationTime, basicInformation.CreationTime, "Unexpected loopback FILE_BASIC_INFORMATION creation time.");
                                TestAssertions.Equal(lastAccessTime, basicInformation.LastAccessTime, "Unexpected loopback FILE_BASIC_INFORMATION last-access time.");
                                TestAssertions.Equal(lastWriteTime, basicInformation.LastWriteTime, "Unexpected loopback FILE_BASIC_INFORMATION last-write time.");
                                TestAssertions.True((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected loopback FILE_BASIC_INFORMATION attributes to include Hidden.");

                                ulong changeTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 11, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> changeTimeResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            ChangeTime = changeTime
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, changeTimeResult.Status, changeTimeResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> changedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation changedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, changedBasicQueryResult.Status, changedBasicQueryResult.Response));
                                TestAssertions.Equal(lastWriteTime, changedBasicInformation.LastWriteTime, "Unexpected loopback FILE_BASIC_INFORMATION last-write time after an explicit ChangeTime update.");
                                TestAssertions.Equal(changeTime, changedBasicInformation.ChangeTime, "Unexpected loopback FILE_BASIC_INFORMATION change time after an explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> networkOpenQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NetworkOpenInformation));
                                FileNetworkOpenInformation networkOpenInformation = FileNetworkOpenInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, networkOpenQueryResult.Status, networkOpenQueryResult.Response));
                                TestAssertions.Equal(64UL, networkOpenInformation.AllocationSize, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, networkOpenInformation.EndOfFile, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION EOF size.");
                                TestAssertions.Equal(changeTime, networkOpenInformation.ChangeTime, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION change time after the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.InternalInformation));
                                FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, internalInformationQueryResult.Status, internalInformationQueryResult.Response));
                                TestAssertions.Equal(openState.PersistentFileId, internalInformation.IndexNumber, "Unexpected loopback FILE_INTERNAL_INFORMATION index number.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> allInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileAllInformation allInformation = FileAllInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, allInformationQueryResult.Status, allInformationQueryResult.Response));
                                TestAssertions.Equal("notes.txt", allInformation.NameInformation.FileName, "Unexpected loopback FILE_ALL_INFORMATION name payload.");
                                TestAssertions.Equal(64UL, allInformation.StandardInformation.AllocationSize, "Unexpected loopback FILE_ALL_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, allInformation.StandardInformation.EndOfFile, "Unexpected loopback FILE_ALL_INFORMATION EOF size.");
                                TestAssertions.Equal(changeTime, allInformation.BasicInformation.ChangeTime, "Unexpected loopback FILE_ALL_INFORMATION change time after the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsSizeInformation fileSystemSizeInformation = FileFsSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemSizeQueryResult.Status, fileSystemSizeQueryResult.Response));
                                TestAssertions.True(fileSystemSizeInformation.TotalAllocationUnits >= fileSystemSizeInformation.AvailableAllocationUnits, "Expected loopback FILE_FS_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.True(fileSystemSizeInformation.SectorsPerAllocationUnit > 0, "Expected loopback FILE_FS_SIZE_INFORMATION sectors per allocation unit to be positive.");
                                TestAssertions.True(fileSystemSizeInformation.BytesPerSector > 0, "Expected loopback FILE_FS_SIZE_INFORMATION bytes per sector to be positive.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemVolumeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.VolumeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsVolumeInformation fileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemVolumeQueryResult.Status, fileSystemVolumeQueryResult.Response));
                                TestAssertions.True(fileSystemVolumeInformation.VolumeSerialNumber != 0, "Expected loopback FILE_FS_VOLUME_INFORMATION serial numbers to be populated.");
                                TestAssertions.True(fileSystemVolumeInformation.VolumeLabel.Length != 0, "Expected loopback FILE_FS_VOLUME_INFORMATION labels to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemAttributeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.AttributeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsAttributeInformation fileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemAttributeQueryResult.Status, fileSystemAttributeQueryResult.Response));
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.CasePreservedNames) != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION to preserve filename casing.");
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.UnicodeOnDisk) != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION to advertise Unicode support.");
                                TestAssertions.True(fileSystemAttributeInformation.FileSystemName.Length != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION filesystem names to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemDeviceQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.DeviceInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsDeviceInformation fileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemDeviceQueryResult.Status, fileSystemDeviceQueryResult.Response));
                                TestAssertions.Equal(FileSystemDeviceType.Disk, fileSystemDeviceInformation.DeviceType, "Expected loopback FILE_FS_DEVICE_INFORMATION to identify a disk-backed share.");
                                TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.RemoteDevice) != 0, "Expected loopback FILE_FS_DEVICE_INFORMATION to advertise a remote device.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemFullSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.FullSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsFullSizeInformation fileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemFullSizeQueryResult.Status, fileSystemFullSizeQueryResult.Response));
                                TestAssertions.True(fileSystemFullSizeInformation.TotalAllocationUnits >= fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected loopback FILE_FS_FULL_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected loopback FILE_FS_FULL_SIZE_INFORMATION caller and actual availability to match for the bounded slice.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSectorSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SectorSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsSectorSizeInformation fileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemSectorSizeQueryResult.Status, fileSystemSectorSizeQueryResult.Response));
                                TestAssertions.True(fileSystemSectorSizeInformation.LogicalBytesPerSector > 0, "Expected loopback FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector to be positive.");
                                TestAssertions.True((fileSystemSectorSizeInformation.Flags & FileSystemSectorSizeFlags.AlignedDevice) != 0, "Expected loopback FILE_FS_SECTOR_SIZE_INFORMATION to advertise aligned devices.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyDisableResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue,
                                            LastAccessTime = UInt64.MaxValue,
                                            LastWriteTime = UInt64.MaxValue,
                                            ChangeTime = UInt64.MaxValue
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, stickyDisableResult.Status, stickyDisableResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> suppressedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0, minimumCount: 1));
                                client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, suppressedReadResult.Status, suppressedReadResult.Response);

                                OpenCifsServerOperationResult<Smb2WriteResponse> suppressedWriteResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x41 }, 0));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, suppressedWriteResult.Status, suppressedWriteResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation suppressedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, suppressedBasicQueryResult.Status, suppressedBasicQueryResult.Response));
                                TestAssertions.Equal(creationTime, suppressedBasicInformation.CreationTime, "Expected loopback sticky timestamp directives to preserve creation time.");
                                TestAssertions.Equal(lastAccessTime, suppressedBasicInformation.LastAccessTime, "Expected loopback reads through a sticky-disabled handle to preserve last-access time.");
                                TestAssertions.Equal(lastWriteTime, suppressedBasicInformation.LastWriteTime, "Expected loopback writes through a sticky-disabled handle to preserve last-write time.");
                                TestAssertions.Equal(changeTime, suppressedBasicInformation.ChangeTime, "Expected loopback metadata mutations through a sticky-disabled handle to preserve change time.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyEnableResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue - 1,
                                            LastAccessTime = UInt64.MaxValue - 1,
                                            LastWriteTime = UInt64.MaxValue - 1,
                                            ChangeTime = UInt64.MaxValue - 1
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, stickyEnableResult.Status, stickyEnableResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> resumedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0, minimumCount: 1));
                                client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, resumedReadResult.Status, resumedReadResult.Response);

                                OpenCifsServerOperationResult<Smb2WriteResponse> resumedWriteResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x42 }, 1));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, resumedWriteResult.Status, resumedWriteResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation resumedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, resumedBasicQueryResult.Status, resumedBasicQueryResult.Response));
                                TestAssertions.Equal(creationTime, resumedBasicInformation.CreationTime, "Expected loopback automatic timestamp updates to leave creation time unchanged.");
                                TestAssertions.True(resumedBasicInformation.LastAccessTime != lastAccessTime, "Expected loopback reads after sticky re-enable to advance last-access time.");
                                TestAssertions.True(resumedBasicInformation.LastWriteTime != lastWriteTime, "Expected loopback writes after sticky re-enable to advance last-write time.");
                                TestAssertions.True(resumedBasicInformation.ChangeTime != changeTime, "Expected loopback metadata mutations after sticky re-enable to advance change time.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedNetworkOpenQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NetworkOpenInformation));
                                FileNetworkOpenInformation resumedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, resumedNetworkOpenQueryResult.Status, resumedNetworkOpenQueryResult.Response));
                                TestAssertions.Equal(resumedBasicInformation.LastWriteTime, resumedNetworkOpenInformation.LastWriteTime, "Expected loopback FILE_NETWORK_OPEN_INFORMATION last-write time to match FILE_BASIC_INFORMATION after automatic updates resume.");
                                TestAssertions.Equal(resumedBasicInformation.ChangeTime, resumedNetworkOpenInformation.ChangeTime, "Expected loopback FILE_NETWORK_OPEN_INFORMATION change time to match FILE_BASIC_INFORMATION after automatic updates resume.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetRenameInfoRequest(openState.PersistentFileId, openState.VolatileFileId, "folder/renamed.txt"));
                                client.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, renameResult.Status, renameResult.Response, "folder/renamed.txt");
                                TestAssertions.Equal("folder\\renamed.txt", openState.Path, "Expected successful loopback rename to update the tracked open path.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> nameResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NameInformation));
                                FileNameInformation fileNameInformation = FileNameInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, nameResult.Status, nameResult.Response));
                                TestAssertions.Equal("folder\\renamed.txt", fileNameInformation.FileName, "Unexpected loopback FILE_NAME_INFORMATION path after rename.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(openState.PersistentFileId, openState.VolatileFileId, deletePending: true));
                                client.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, dispositionResult.Status, dispositionResult.Response, deletePending: true);
                                TestAssertions.True(openState.IsDeletePending, "Expected successful loopback disposition updates to mark the tracked open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> deletePendingResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation deletePendingInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, deletePendingResult.Status, deletePendingResult.Response));
                                TestAssertions.True(deletePendingInformation.DeletePending, "Expected loopback FILE_DISPOSITION_INFORMATION to propagate to FILE_STANDARD_INFORMATION.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback metadata open after close.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "folder", "renamed.txt")), "Expected the delete-pending renamed file to be removed after the last close.");
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
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRejectDispositionDeletePendingOnReadOnlyFilesAndDirectories",
                        displayName: "Client and server loopback reject FILE_DISPOSITION_INFORMATION delete-pending on read-only files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-file.txt",
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState readOnlyFileOpen = client.ApplyCreateResult(treeId, "readonly-file.txt", readOnlyFileOpenResult.Status, readOnlyFileOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyFileDisposition = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, deletePending: true));
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetDispositionInfoResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileDisposition.Status, readOnlyFileDisposition.Response, deletePending: true),
                                    "Expected loopback read-only file disposition failures to propagate through the client state surface.");
                                TestAssertions.False(readOnlyFileOpen.IsDeletePending, "Expected failed loopback read-only file disposition requests not to mark the tracked open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyFileStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation readOnlyFileStandard = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileStandardResult.Status, readOnlyFileStandardResult.Response));
                                TestAssertions.False(readOnlyFileStandard.DeletePending, "Expected loopback read-only file standard information not to report delete-pending after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyFileClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId));
                                client.ApplyCloseResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileClose.Status, readOnlyFileClose.Response);
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the loopback read-only file to remain after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                OpenState readOnlyDirectoryOpen = client.ApplyCreateResult(treeId, "readonly-directory", readOnlyDirectoryOpenResult.Status, readOnlyDirectoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyDirectoryDisposition = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, deletePending: true));
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetDispositionInfoResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryDisposition.Status, readOnlyDirectoryDisposition.Response, deletePending: true),
                                    "Expected loopback read-only directory disposition failures to propagate through the client state surface.");
                                TestAssertions.False(readOnlyDirectoryOpen.IsDeletePending, "Expected failed loopback read-only directory disposition requests not to mark the tracked directory open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyDirectoryStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation readOnlyDirectoryStandard = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryStandardResult.Status, readOnlyDirectoryStandardResult.Response));
                                TestAssertions.False(readOnlyDirectoryStandard.DeletePending, "Expected loopback read-only directory standard information not to report delete-pending after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryClose.Status, readOnlyDirectoryClose.Response);
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the loopback read-only directory to remain after the failed disposition request.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback read-only disposition slice to close all tracked opens.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerApplyReadOnlyClearingMetadataUpdatesAndRejectAttributeOnlyFileReads",
                        displayName: "Client and server loopback apply read-only-clearing attribute-only FILE_BASIC_INFORMATION updates and reject file reads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-attributes.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly | System.IO.FileAttributes.Hidden);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-attributes.txt",
                                        desiredAccess: 0x00000180U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState attributeOnlyOpen = client.ApplyCreateResult(treeId, "readonly-attributes.txt", attributeOnlyOpenResult.Status, attributeOnlyOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> clearReadOnlyResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        attributeOnlyOpen.PersistentFileId,
                                        attributeOnlyOpen.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }));
                                client.ApplySetInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, clearReadOnlyResult.Status, clearReadOnlyResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, basicQueryResult.Status, basicQueryResult.Response));
                                TestAssertions.False((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.ReadOnly) != 0, "Expected loopback FILE_BASIC_INFORMATION updates to clear the read-only attribute.");
                                TestAssertions.True((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected loopback FILE_BASIC_INFORMATION updates to preserve the hidden attribute.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> deniedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, length: 1, offset: 0));
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedReadResult.Status, "Expected loopback attribute-only metadata opens not to grant file-read data access.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, deniedReadResult.Status, deniedReadResult.Response),
                                    "Expected loopback denied reads on attribute-only metadata opens to propagate through the client state surface.");
                                TestAssertions.False((File.GetAttributes(readOnlyFilePath) & System.IO.FileAttributes.ReadOnly) != 0, "Expected the loopback backing file to have its read-only attribute cleared.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId));
                                client.ApplyCloseResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, attributeOnlyCloseResult.Status, attributeOnlyCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback attribute-only metadata open after close.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRejectInvalidIdentifiersAcrossMetadataSurface",
                        displayName: "Client and server loopback reject invalid session, tree, and open identifiers across the bounded metadata surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropMetadataIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "metadata.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "metadata.txt", desiredAccess: 0xC0010080U, createDisposition: Smb2CreateDisposition.Open));
                                OpenState fileOpen = client.ApplyCreateResult(treeId, "metadata.txt", fileOpenResult.Status, fileOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "folder", desiredAccess: 0x80000000U, createDisposition: Smb2CreateDisposition.Open, createOptions: Smb2CreateOptions.DirectoryFile));
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "folder", directoryOpenResult.Status, directoryOpenResult.Response);

                                Smb2QueryInfoRequest queryInfoRequest = client.CreateQueryInfoRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId, FileInformationClass.BasicInformation);
                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> invalidQuerySessionResult = server.HandleQueryInfo(client.SessionId.Value + 1, treeId, queryInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidQuerySessionResult.Status, "Expected loopback query-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidQuerySessionResult.Status, invalidQuerySessionResult.Response),
                                    "Expected the client to surface invalid-session query-info failures.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> invalidQueryTreeResult = server.HandleQueryInfo(client.SessionId.Value, treeId + 1, queryInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidQueryTreeResult.Status, "Expected loopback query-info requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidQueryTreeResult.Status, invalidQueryTreeResult.Response),
                                    "Expected the client to surface invalid-tree query-info failures.");

                                Smb2SetInfoRequest setInfoRequest = client.CreateSetBasicInfoRequest(
                                    fileOpen.PersistentFileId,
                                    fileOpen.VolatileFileId,
                                    new FileBasicInformation
                                    {
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidSetSessionResult = server.HandleSetInfo(client.SessionId.Value + 1, treeId, setInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidSetSessionResult.Status, "Expected loopback set-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidSetSessionResult.Status, invalidSetSessionResult.Response),
                                    "Expected the client to surface invalid-session set-info failures.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidSetTreeResult = server.HandleSetInfo(client.SessionId.Value, treeId + 1, setInfoRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidSetTreeResult.Status, "Expected loopback set-info requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetInfoResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidSetTreeResult.Status, invalidSetTreeResult.Response),
                                    "Expected the client to surface invalid-tree set-info failures.");

                                Smb2QueryDirectoryRequest queryDirectoryRequest = client.CreateQueryDirectoryRequest(
                                    directoryOpen.PersistentFileId,
                                    directoryOpen.VolatileFileId,
                                    FileInformationClass.DirectoryInformation,
                                    outputBufferLength: 512,
                                    fileNamePattern: "*",
                                    flags: Smb2QueryDirectoryFlags.RestartScans);
                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> invalidDirectorySessionResult = server.HandleQueryDirectory(client.SessionId.Value + 1, treeId, queryDirectoryRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidDirectorySessionResult.Status, "Expected loopback query-directory requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryDirectoryResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, invalidDirectorySessionResult.Status, invalidDirectorySessionResult.Response),
                                    "Expected the client to surface invalid-session query-directory failures.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> invalidDirectoryTreeResult = server.HandleQueryDirectory(client.SessionId.Value, treeId + 1, queryDirectoryRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidDirectoryTreeResult.Status, "Expected loopback query-directory requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyQueryDirectoryResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, invalidDirectoryTreeResult.Status, invalidDirectoryTreeResult.Response),
                                    "Expected the client to surface invalid-tree query-directory failures.");

                                Smb2IoctlRequest ioctlRequest = client.CreateEnumerateSnapshotsRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId, maxOutputResponse: 128);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> invalidIoctlSessionResult = server.HandleIoctl(client.SessionId.Value + 1, treeId, ioctlRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidIoctlSessionResult.Status, "Expected loopback IOCTL requests with an unknown session identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyIoctlResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidIoctlSessionResult.Status, invalidIoctlSessionResult.Response),
                                    "Expected the client to surface invalid-session IOCTL failures.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> invalidIoctlTreeResult = server.HandleIoctl(client.SessionId.Value, treeId + 1, ioctlRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidIoctlTreeResult.Status, "Expected loopback IOCTL requests with an unknown tree identifier to be rejected.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyIoctlResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, invalidIoctlTreeResult.Status, invalidIoctlTreeResult.Response),
                                    "Expected the client to surface invalid-tree IOCTL failures.");

                                Smb2ChangeNotifyRequest notifyRequest = client.CreateChangeNotifyRequest(
                                    directoryOpen.PersistentFileId,
                                    directoryOpen.VolatileFileId,
                                    FileNotifyChangeFilter.FileName,
                                    watchTree: false,
                                    outputBufferLength: 512);
                                OpenCifsServerAsyncResponse invalidNotifySessionResult = server.HandleChangeNotify(
                                    client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId, sessionId: client.SessionId.Value + 1),
                                    notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifySessionResult.Header.Status, "Expected loopback change-notify requests with an unknown session identifier to be rejected.");
                                client.ApplyResponseHeader(invalidNotifySessionResult.Header);

                                OpenCifsServerAsyncResponse invalidNotifyTreeResult = server.HandleChangeNotify(
                                    client.CreateRequestHeader(Smb2Command.ChangeNotify, treeId + 1, sessionId: client.SessionId.Value),
                                    notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifyTreeResult.Header.Status, "Expected loopback change-notify requests with an unknown tree identifier to be rejected.");
                                client.ApplyResponseHeader(invalidNotifyTreeResult.Header);

                                OpenCifsServerOperationResult<Smb2CloseResponse> fileCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(fileOpen.PersistentFileId, fileOpen.VolatileFileId));
                                client.ApplyCloseResult(fileOpen.PersistentFileId, fileOpen.VolatileFileId, fileCloseResult.Status, fileCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerEnumerateDirectoryEntries",
                        displayName: "Client and server loopback enumerate directory entries through bounded query-directory requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "alpha");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "beta.log"), "beta");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "folder",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "folder", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the loopback directory open.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> firstEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.DirectoryInformation,
                                        outputBufferLength: 512,
                                        fileNamePattern: "*",
                                        flags: Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry));
                                FileDirectoryInformationEntry[] firstEntries = FileDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, firstEnumerationResult.Status, firstEnumerationResult.Response));
                                TestAssertions.Equal(1, firstEntries.Length, "Expected the first loopback directory enumeration to honor ReturnSingleEntry.");
                                TestAssertions.Equal("alpha.txt", firstEntries[0].FileName, "Unexpected first loopback directory entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> resumedEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.DirectoryInformation,
                                        outputBufferLength: 4096));
                                FileDirectoryInformationEntry[] resumedEntries = FileDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, resumedEnumerationResult.Status, resumedEnumerationResult.Response));
                                TestAssertions.Equal(2, resumedEntries.Length, "Expected the resumed loopback directory enumeration to return the remaining entries.");
                                TestAssertions.Equal("beta.log", resumedEntries[0].FileName, "Unexpected second loopback directory entry.");
                                TestAssertions.Equal("nested", resumedEntries[1].FileName, "Unexpected final loopback directory entry.");
                                TestAssertions.True(
                                    (resumedEntries[1].FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0,
                                    "Expected loopback directory enumeration to preserve directory attributes.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> filteredEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.FullDirectoryInformation,
                                        outputBufferLength: 4096,
                                        fileNamePattern: "*.txt",
                                        flags: Smb2QueryDirectoryFlags.RestartScans));
                                FileFullDirectoryInformationEntry[] filteredEntries = FileFullDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, filteredEnumerationResult.Status, filteredEnumerationResult.Response));
                                TestAssertions.Equal(1, filteredEntries.Length, "Expected the filtered loopback directory enumeration to return a single matching entry.");
                                TestAssertions.Equal("alpha.txt", filteredEntries[0].FileName, "Unexpected filtered loopback directory entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> bothEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.BothDirectoryInformation,
                                        outputBufferLength: 4096,
                                        fileNamePattern: "*.log",
                                        flags: Smb2QueryDirectoryFlags.RestartScans));
                                FileBothDirectoryInformationEntry[] bothEntries = FileBothDirectoryInformationEntry.DecodeEntries(
                                    client.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, bothEnumerationResult.Status, bothEnumerationResult.Response));
                                TestAssertions.Equal(1, bothEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION loopback enumeration to return a single filtered entry.");
                                TestAssertions.Equal("beta.log", bothEntries[0].FileName, "Unexpected FILE_BOTH_DIR_INFORMATION loopback entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> exhaustedEnumerationResult = server.HandleQueryDirectory(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryDirectoryRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        FileInformationClass.FullDirectoryInformation,
                                        outputBufferLength: 4096));
                                byte[] exhaustedEnumerationBytes = client.ApplyQueryDirectoryResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    exhaustedEnumerationResult.Status,
                                    exhaustedEnumerationResult.Response);
                                TestAssertions.Equal(0, exhaustedEnumerationBytes.Length, "Expected exhausted loopback directory enumeration to return an empty payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback directory open after close.");
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
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRenameDirectoriesThroughBoundedSetInfo",
                        displayName: "Client and server loopback rename directories through bounded FILE_RENAME_INFORMATION",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "source"));
                            File.WriteAllText(Path.Combine(sharePath, "source", "child.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest childOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "source/child.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> childOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, childOpenRequest);
                                OpenState childOpen = client.ApplyCreateResult(treeId, "source/child.txt", childOpenResult.Status, childOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> childAllocationResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(childOpen.PersistentFileId, childOpen.VolatileFileId, 96));
                                client.ApplySetInfoResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childAllocationResult.Status, childAllocationResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "source",
                                    desiredAccess: 0x80010000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, directoryOpenRequest);
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "source", directoryOpenResult.Status, directoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> directoryRenameResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetRenameInfoRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, "archive/renamed-folder"));
                                client.ApplySetRenameInfoResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryRenameResult.Status, directoryRenameResult.Response, "archive/renamed-folder");
                                TestAssertions.Equal("archive\\renamed-folder", directoryOpen.Path, "Expected the loopback directory rename to update the tracked open path.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedDirectoryNameResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, FileInformationClass.NameInformation));
                                FileNameInformation renamedDirectoryName = FileNameInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, renamedDirectoryNameResult.Status, renamedDirectoryNameResult.Response));
                                TestAssertions.Equal("archive\\renamed-folder", renamedDirectoryName.FileName, "Unexpected loopback FILE_NAME_INFORMATION path after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> movedChildOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "archive/renamed-folder/child.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState movedChildOpen = client.ApplyCreateResult(treeId, "archive/renamed-folder/child.txt", movedChildOpenResult.Status, movedChildOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> movedChildStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation movedChildStandardInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, movedChildStandardResult.Status, movedChildStandardResult.Response));
                                TestAssertions.Equal(96UL, movedChildStandardInformation.AllocationSize, "Expected declared allocation state to move with the renamed directory subtree.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> movedChildCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId));
                                client.ApplyCloseResult(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, movedChildCloseResult.Status, movedChildCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> oldPathOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "source/child.txt", createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, oldPathOpenResult.Status, "Expected the old loopback child path to disappear after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear directory and moved-child opens after the bounded loopback rename slice closes them.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "archive", "renamed-folder")), "Expected the renamed loopback directory to remain at its destination path.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackLockingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackLocking",
                displayName: "Loopback byte-range locking coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackLocking",
                        caseId: "ClientAndServerApplyByteRangeLocksAndRejectConflicts",
                        displayName: "Client and server loopback apply byte-range locks and reject conflicting lock and read requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "0123456789");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> firstCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "locked.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState firstOpen = client.ApplyCreateResult(treeId, "locked.txt", firstCreateResult.Status, firstCreateResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> secondCreateResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "locked.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState secondOpen = client.ApplyCreateResult(treeId, "locked.txt", secondCreateResult.Status, secondCreateResult.Response);
                                TestAssertions.Equal(2, client.OpenCount, "Expected the client to track both loopback locking opens.");

                                Smb2LockRequest firstLockRequest = client.CreateLockRequest(
                                    firstOpen.PersistentFileId,
                                    firstOpen.VolatileFileId,
                                    new Smb2LockElement
                                    {
                                        Offset = 2,
                                        Length = 4,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    });
                                OpenCifsServerOperationResult<Smb2LockResponse> firstLockResult = server.HandleLock(client.SessionId.Value, treeId, firstLockRequest);
                                client.ApplyLockResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstLockResult.Status, firstLockResult.Response);

                                Smb2LockRequest conflictingLockRequest = client.CreateLockRequest(
                                    secondOpen.PersistentFileId,
                                    secondOpen.VolatileFileId,
                                    new Smb2LockElement
                                    {
                                        Offset = 2,
                                        Length = 4,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    });
                                OpenCifsServerOperationResult<Smb2LockResponse> conflictingLockResult = server.HandleLock(client.SessionId.Value, treeId, conflictingLockRequest);
                                TestAssertions.Equal(NtStatus.LockNotGranted, conflictingLockResult.Status, "Expected a conflicting loopback lock request to fail.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> conflictingReadResult = server.HandleRead(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateReadRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId, 2, 2));
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingReadResult.Status, "Expected a competing loopback read to fail inside the exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = server.HandleLock(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateLockRequest(
                                        firstOpen.PersistentFileId,
                                        firstOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 2,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }));
                                client.ApplyLockResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, unlockResult.Status, unlockResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("AB");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateWriteRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId, payload, 2));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(secondOpen.PersistentFileId, secondOpen.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback post-unlock write count.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> firstCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(firstOpen.PersistentFileId, firstOpen.VolatileFileId));
                                client.ApplyCloseResult(firstOpen.PersistentFileId, firstOpen.VolatileFileId, firstCloseResult.Status, firstCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondCloseResult = server.HandleClose(
                                    client.SessionId.Value,
                                    treeId,
                                    client.CreateCloseRequest(secondOpen.PersistentFileId, secondOpen.VolatileFileId));
                                client.ApplyCloseResult(secondOpen.PersistentFileId, secondOpen.VolatileFileId, secondCloseResult.Status, secondCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear both loopback locking opens after close.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the loopback IOCTL suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor LoopbackIoctlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackIoctl",
                displayName: "Loopback IOCTL coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackIoctl",
                        caseId: "ClientAndServerHandleValidateNegotiateAndSnapshotEnumerationAndRejectUnsupportedWildcardIoctlsWithHeaders",
                        displayName: "Client and server loopback handle validate-negotiate and bounded snapshot enumeration and reject unsupported wildcard SMB2 IOCTL requests with headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropIoctl_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId ?? throw new InvalidOperationException("Expected the loopback client session to be authenticated before IOCTL validation.");

                                Smb2Header validateIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: sessionId);
                                Smb2NegotiateRequest validateNegotiateRequest = client.CreateNegotiateRequest();
                                Smb2IoctlRequest validateIoctlRequest = client.CreateConnectionIoctlRequest(
                                    (uint)FsctlCode.ValidateNegotiateInfo,
                                    new ValidateNegotiateInfoRequest
                                    {
                                        Capabilities = validateNegotiateRequest.Capabilities,
                                        ClientGuid = validateNegotiateRequest.ClientGuid,
                                        SecurityMode = validateNegotiateRequest.SecurityMode,
                                        Dialects = validateNegotiateRequest.Dialects
                                    }.ToByteArray(),
                                    maxOutputResponse: 256);
                                server.ValidateAndAcceptRequestHeader(validateIoctlHeader, Smb2Command.Ioctl, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> validateIoctlResult = server.HandleIoctl(sessionId, treeId, validateIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(validateIoctlHeader, validateIoctlResult.Status, sessionId: sessionId, treeId: treeId));
                                TestAssertions.Equal(NtStatus.Success, validateIoctlResult.Status, "Expected loopback validate-negotiate IOCTL requests to succeed.");
                                byte[] validateOutputBuffer = client.ApplyConnectionIoctlResult(validateIoctlResult.Status, validateIoctlResult.Response);
                                ValidateNegotiateInfoResponse validateIoctlResponse = ValidateNegotiateInfoResponse.ReadFrom(validateOutputBuffer);
                                TestAssertions.Equal(client.NegotiatedDialect!.Value, validateIoctlResponse.Dialect, "Expected loopback validate-negotiate responses to preserve the negotiated dialect.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "notes.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId.Value, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                OpenState openState = client.ApplyCreateResult(treeId, "notes.txt", createResult.Status, createResult.Response);

                                Smb2Header openIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: client.SessionId.Value);
                                Smb2IoctlRequest openIoctlRequest = client.CreateEnumerateSnapshotsRequest(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    maxOutputResponse: 512);
                                server.ValidateAndAcceptRequestHeader(openIoctlHeader, Smb2Command.Ioctl, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> openIoctlResult = server.HandleIoctl(client.SessionId.Value, treeId, openIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openIoctlHeader, openIoctlResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                TestAssertions.Equal(NtStatus.Success, openIoctlResult.Status, "Expected bounded snapshot enumeration to succeed in loopback coverage.");
                                Smb2IoctlResponseValidator.Validate(openIoctlResult.Response);
                                SrvSnapshotArray snapshotArray = client.ApplyEnumerateSnapshotsResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    openIoctlResult.Status,
                                    openIoctlResult.Response);
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected the bounded loopback snapshot enumeration slice to expose no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected the bounded loopback snapshot enumeration slice to return an empty snapshot list.");

                                Smb2Header wildcardIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: client.SessionId.Value);
                                Smb2IoctlRequest wildcardIoctlRequest = client.CreateConnectionIoctlRequest(
                                    (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    maxOutputResponse: 512);
                                server.ValidateAndAcceptRequestHeader(wildcardIoctlHeader, Smb2Command.Ioctl, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> wildcardIoctlResult = server.HandleIoctl(client.SessionId.Value, treeId, wildcardIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(wildcardIoctlHeader, wildcardIoctlResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                TestAssertions.Equal(NtStatus.NotSupported, wildcardIoctlResult.Status, "Expected unsupported wildcard loopback IOCTL requests to remain non-implemented.");
                                TestAssertions.Equal(UInt64.MaxValue, wildcardIoctlResult.Response.PersistentFileId, "Expected wildcard loopback IOCTL responses to preserve the wildcard file identifier.");

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId.Value);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(client.SessionId.Value, treeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);

                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback IOCTL close path to clear the tracked open.");
                                TestAssertions.Equal(4, client.AvailableCredits, "Expected loopback IOCTL requests, including snapshot enumeration, to preserve the negotiated client credit window.");
                                TestAssertions.Equal(4, server.AvailableCredits, "Expected loopback IOCTL requests, including snapshot enumeration, to preserve the negotiated server credit window.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        private static OpenCifsServerHost CreateServerHost(string? sharePath = null, OpenCifsServerSharedState? sharedState = null)
        {
            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
            {
                ServerName = "LAB-SERVER"
            }, sharedState);
            host.RegisterShare(new OpenCifsServerFileSystemShare
            {
                ShareName = "public",
                RootPath = sharePath ?? "SampleShare",
                CreateRootIfMissing = true
            });
            host.RegisterAccount(new OpenCifsServerAccount
            {
                UserName = "alice",
                UserDomain = "WORKGROUP",
                Password = "Password123!"
            });
            return host;
        }

        private static ulong AuthenticateLoopbackSession(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential)
        {
            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);
            return successResult.SessionId;
        }

        private static uint AuthenticateLoopbackSessionAndTree(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential)
        {
            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("public");
            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
            client.ApplyTreeConnectResult("public", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);
            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree before loopback file operations.");
            return treeConnectResult.TreeId;
        }

        private static uint AuthenticateLoopbackSessionAndTreeWithHeaders(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential, ushort creditRequest)
        {
            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest);

            Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("public");
            server.ValidateAndAcceptRequestHeader(treeConnectHeader, Smb2Command.TreeConnect, expectedSessionId: sessionId);
            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
            client.ApplyTreeConnectResult("public", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree before compounded loopback file operations.");
            TestAssertions.Equal(creditRequest, (ushort)client.AvailableCredits, "Expected header-wrapped authenticate and tree setup to preserve the negotiated client credit window.");
            TestAssertions.Equal(creditRequest, (ushort)server.AvailableCredits, "Expected header-wrapped authenticate and tree setup to preserve the negotiated server credit window.");
            return treeConnectResult.TreeId;
        }

        private static ulong AuthenticateLoopbackSessionWithHeaders(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential, ushort creditRequest)
        {
            Smb2Header negotiateHeader = client.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: creditRequest);
            Smb2NegotiateRequest negotiateRequest = client.CreateNegotiateRequest();
            server.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
            Smb2NegotiateResponse negotiateResponse = server.HandleNegotiate(negotiateRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(negotiateHeader, NtStatus.Success));
            client.ApplyNegotiateResponse(negotiateResponse);

            Smb2Header initialSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
            Smb2SessionSetupRequest initialSessionRequest = client.CreateSessionSetupRequest(credential);
            server.ValidateAndAcceptRequestHeader(initialSessionHeader, Smb2Command.SessionSetup);
            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, initialSessionRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(initialSessionHeader, challengeResult.Status, sessionId: challengeResult.SessionId));

            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            Smb2Header authenticateSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResult.SessionId);
            server.ValidateAndAcceptRequestHeader(authenticateSessionHeader, Smb2Command.SessionSetup, expectedSessionId: challengeResult.SessionId);
            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(authenticateSessionHeader, successResult.Status, sessionId: successResult.SessionId));
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

            TestAssertions.Equal(creditRequest, (ushort)client.AvailableCredits, "Expected header-wrapped session setup to preserve the negotiated client credit window.");
            TestAssertions.Equal(creditRequest, (ushort)server.AvailableCredits, "Expected header-wrapped session setup to preserve the negotiated server credit window.");
            return successResult.SessionId;
        }

        private static OpenCifsClientSession CreateNegotiatedClient(OpenCifsServerHost server)
        {
            OpenCifsClientSession client = CreateClient();
            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
            Smb2NegotiateResponse response = server.HandleNegotiate(request);
            client.ApplyNegotiateResponse(response);
            return client;
        }

        private static OpenCifsClientSession CreateClient()
        {
            return new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER"
            });
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

        private static byte[] CreateLargePayloadBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)('a' + (index % 19)));
            }

            return bytes;
        }

        private static void DeleteDirectoryForcefully(string rootPath)
        {
            if (!Directory.Exists(rootPath))
            {
                return;
            }

            foreach (string filePath in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(filePath, System.IO.FileAttributes.Normal);
            }

            foreach (string directoryPath in Directory.EnumerateDirectories(rootPath, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(directoryPath, System.IO.FileAttributes.Directory);
            }

            File.SetAttributes(rootPath, System.IO.FileAttributes.Directory);
            Directory.Delete(rootPath, recursive: true);
        }
    }
}

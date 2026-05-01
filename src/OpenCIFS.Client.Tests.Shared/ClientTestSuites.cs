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
                    ClientPrimarySuite(),
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
                        caseId: "ClientStatusExceptionsReturnNormalizedCategoriesForRepresentativeNtStatusValues",
                        displayName: "Client status exceptions return normalized categories for representative NTSTATUS values",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Equal(OpenCifsErrorCategory.NotFound, new OpenCifsStatusException(Smb2Command.Create, NtStatus.ObjectNameNotFound).Category, "Expected STATUS_OBJECT_NAME_NOT_FOUND to normalize to NotFound.");
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, new OpenCifsStatusException(Smb2Command.SetInfo, NtStatus.AccessDenied).Category, "Expected STATUS_ACCESS_DENIED to normalize to AccessDenied.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Conflict, new OpenCifsStatusException(Smb2Command.Create, NtStatus.SharingViolation).Category, "Expected STATUS_SHARING_VIOLATION to normalize to Conflict.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Unsupported, new OpenCifsStatusException(Smb2Command.Ioctl, NtStatus.NotSupported).Category, "Expected STATUS_NOT_SUPPORTED to normalize to Unsupported.");
                            TestAssertions.Equal(OpenCifsErrorCategory.ProtocolError, new OpenCifsStatusException(Smb2Command.QueryInfo, NtStatus.BufferTooSmall).Category, "Expected STATUS_BUFFER_TOO_SMALL to normalize to ProtocolError.");
                            TestAssertions.Equal(OpenCifsErrorCategory.IoError, new OpenCifsStatusException(Smb2Command.Close, NtStatus.FileClosed).Category, "Expected STATUS_FILE_CLOSED to normalize to IoError.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Cancelled, new OpenCifsStatusException(Smb2Command.ChangeNotify, NtStatus.Cancelled).Category, "Expected STATUS_CANCELLED to normalize to Cancelled.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "ClientPublicSurfaceExposesTypedExceptionsForRepresentativeStateAndProtocolFailures",
                        displayName: "Client public surface exposes typed exceptions for representative state and protocol failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsStatusException statusException = new OpenCifsStatusException(Smb2Command.Create, NtStatus.ObjectNameNotFound);
                            TestAssertions.True(statusException is OpenCifsClientException, "Expected SMB status failures to derive from the typed client exception hierarchy.");

                            OpenCifsClientConnection disconnectedConnection = new OpenCifsClientConnection(new OpenCifsClientOptions());
                            TestAssertions.Throws<OpenCifsClientStateException>(
                                () => disconnectedConnection.TreeConnectAsync("public", token).GetAwaiter().GetResult(),
                                "Expected tree connect before authentication to raise a typed client-state exception.");

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyResponseHeader(CreateResponseHeader(requestHeader, flags: Smb2HeaderFlags.None)),
                                "Expected malformed response headers on the advanced session surface to raise a typed client-protocol exception.");
                            return Task.CompletedTask;
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
                        displayName: "Client negotiate request advertises the implemented SMB 2.0.2 through SMB 3.0.2 dialects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest request = session.CreateNegotiateRequest();

                            if (request.Dialects.Length != 4)
                            {
                                throw new InvalidOperationException("Expected exactly four currently implemented client dialects.");
                            }

                            if (request.Dialects[0] != SmbDialect.Smb2002 ||
                                request.Dialects[1] != SmbDialect.Smb21 ||
                                request.Dialects[2] != SmbDialect.Smb30 ||
                                request.Dialects[3] != SmbDialect.Smb302)
                            {
                                throw new InvalidOperationException("Expected SMB 2.0.2 through SMB 3.0.2 to be the currently implemented client dialects.");
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
                                Dialect = SmbDialect.Smb311,
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
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAdvertisesOptInSmb302DialectsWhenEncryptionIsNotPreferred",
                        displayName: "Client negotiate request advertises SMB 3.0 and SMB 3.0.2 while omitting encryption capability when encryption is not preferred",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                PreferEncryption = false
                            });
                            Smb2NegotiateRequest request = session.CreateNegotiateRequest();

                            TestAssertions.Equal(4, request.Dialects.Length, "Expected the opt-in client dialect list to include the bounded SMB 3.0 and SMB 3.0.2 slice.");
                            TestAssertions.Equal(SmbDialect.Smb2002, request.Dialects[0], "Unexpected first opt-in client dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, request.Dialects[1], "Unexpected second opt-in client dialect.");
                            TestAssertions.Equal(SmbDialect.Smb30, request.Dialects[2], "Unexpected third opt-in client dialect.");
                            TestAssertions.Equal(SmbDialect.Smb302, request.Dialects[3], "Unexpected fourth opt-in client dialect.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                request.Capabilities,
                                "Expected the opt-in client negotiate request to advertise the bounded DFS, large-MTU, and leasing capability set.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAdvertisesSmb302DialectsAndEncryptionCapabilityWhenEncryptionIsPreferred",
                        displayName: "Client negotiate request advertises SMB 3.0 and SMB 3.0.2 plus encryption capability when encryption is preferred",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                MaximumDialect = SmbDialect.Smb302,
                                PreferEncryption = true
                            });
                            Smb2NegotiateRequest request = session.CreateNegotiateRequest();

                            TestAssertions.Equal(4, request.Dialects.Length, "Expected the preferred-encryption client dialect list to include the bounded SMB 3.0 and SMB 3.0.2 slice.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                request.Capabilities,
                                "Expected the preferred-encryption client negotiate request to advertise encryption alongside the bounded DFS, large-MTU, and leasing capability set.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientSmb311PreviewAdvertisesDialectAndEmitsTypedNegotiateContextEntries",
                        displayName: "Client SMB 3.1.1 preview advertises the dialect and emits typed negotiate-context entries when opted in",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession defaultSession = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest defaultRequest = defaultSession.CreateNegotiateRequest();
                            TestAssertions.True(
                                Array.IndexOf(defaultRequest.Dialects, SmbDialect.Smb311) < 0,
                                "Expected the default opt-out client to omit SMB 3.1.1 from the advertised dialect list.");
                            TestAssertions.Equal((ushort)0, defaultRequest.NegotiateContextCount, "Expected the default opt-out client to omit SMB 3.1.1 negotiate contexts.");

                            OpenCifsClientSession previewSession = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true,
                                ServerName = "files.example.test"
                            });
                            Smb2NegotiateRequest previewRequest = previewSession.CreateNegotiateRequest();
                            TestAssertions.True(
                                Array.IndexOf(previewRequest.Dialects, SmbDialect.Smb311) >= 0,
                                "Expected the SMB 3.1.1 preview client to include SMB 3.1.1 in the advertised dialect list.");
                            TestAssertions.Equal((ushort)4, previewRequest.NegotiateContextCount, "Expected the SMB 3.1.1 preview client to emit four typed negotiate-context entries.");

                            byte[] wireBytes = previewRequest.ToByteArray();
                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(wireBytes);
                            TestAssertions.Equal((ushort)4, parsedRequest.NegotiateContextCount, "Wire round-trip should preserve the SMB 3.1.1 preview context count.");
                            Smb2NegotiateContextEntry[] decodedEntries = parsedRequest.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(4, decodedEntries.Length, "Wire round-trip should preserve SMB 3.1.1 preview context entries.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decodedEntries[0].ContextType, "First context should be preauth integrity.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decodedEntries[1].ContextType, "Second context should be encryption capabilities.");
                            TestAssertions.Equal(Smb2NegotiateContextType.SigningCapabilities, decodedEntries[2].ContextType, "Third context should be signing capabilities.");
                            TestAssertions.Equal(Smb2NegotiateContextType.Netname, decodedEntries[3].ContextType, "Fourth context should be NETNAME.");

                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Preview should advertise SHA-512 preauth integrity.");
                            TestAssertions.Equal(32, decodedPreauth.Salt.Length, "Preview should generate a 32-byte preauth salt.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(2, decodedEncryption.Ciphers.Length, "Preview should advertise both AES-128-GCM and AES-128-CCM ciphers.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, decodedEncryption.Ciphers[0], "Preview should prefer AES-128-GCM as the first cipher offer.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Ccm, decodedEncryption.Ciphers[1], "Preview should fall back to AES-128-CCM as the second cipher offer.");
                            SigningCapabilities decodedSigning = SigningCapabilities.ReadFrom(decodedEntries[2].Payload);
                            TestAssertions.Equal(3, decodedSigning.SigningAlgorithms.Length, "Preview should advertise three signing algorithms.");
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, decodedSigning.SigningAlgorithms[0], "Preview should prefer AES-GMAC as the first signing offer.");
                            TestAssertions.Equal(SigningAlgorithmId.AesCmac, decodedSigning.SigningAlgorithms[1], "Preview should fall back to AES-CMAC as the second signing offer.");
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, decodedSigning.SigningAlgorithms[2], "Preview should fall back to HMAC-SHA256 as the third signing offer.");
                            NetnameNegotiateContext decodedNetname = NetnameNegotiateContext.ReadFrom(decodedEntries[3].Payload);
                            TestAssertions.Equal("files.example.test", decodedNetname.ServerName, "Preview should advertise the configured server name in NETNAME.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientSmb311PreviewAccumulatesPreauthIntegrityTranscriptAcrossNegotiate",
                        displayName: "Client SMB 3.1.1 preview accumulates the preauth integrity transcript across the negotiate request and response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession defaultSession = new OpenCifsClientSession(new OpenCifsClientOptions());
                            defaultSession.CreateNegotiateRequest();
                            byte[]? defaultHash = defaultSession.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(defaultHash == null, "Expected the default opt-out client to leave the preauth hash unallocated.");

                            OpenCifsClientSession previewSession = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true
                            });
                            Smb2Header requestHeader = previewSession.CreateRequestHeader(Smb2Command.Negotiate);
                            Smb2NegotiateRequest request = previewSession.CreateNegotiateRequest();

                            byte[]? initialHash = previewSession.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(initialHash != null, "Expected the preview opt-in client to allocate the preauth hash accumulator.");
                            TestAssertions.Equal(64, initialHash!.Length, "Expected the SHA-512 preauth hash to be 64 bytes wide.");

                            byte[] zeros = new byte[64];
                            TestAssertions.SequenceEqual(zeros, initialHash, "Expected the preauth hash to start at all zeros per MS-SMB2.");

                            byte[] requestBody = request.ToByteArray();
                            previewSession.AppendPreauthMessageBytes(requestHeader, requestBody);
                            byte[]? afterRequest = previewSession.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterRequest != null && !afterRequest.AsSpan().SequenceEqual(zeros), "Expected the preauth hash to advance after appending the negotiate request.");

                            Smb2Header responseHeader = new Smb2Header
                            {
                                Command = Smb2Command.Negotiate,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                MessageId = requestHeader.MessageId,
                                Signature = new byte[16]
                            };
                            byte[] responseBody = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb302,
                                ServerGuid = Guid.Parse("D9F1A4C2-1234-4567-89AB-CDEF01234567"),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536,
                                SystemTime = 0x01D811223344AA00UL,
                                ServerStartTime = 0x01D811223344BB00UL,
                                SecurityBuffer = Array.Empty<byte>()
                            }.ToByteArray();
                            previewSession.AppendPreauthMessageBytes(responseHeader, responseBody);
                            byte[]? afterResponse = previewSession.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterResponse != null && !afterResponse.AsSpan().SequenceEqual(afterRequest!), "Expected the preauth hash to advance again after appending the negotiate response.");
                            TestAssertions.Equal(64, afterResponse!.Length, "Expected the preauth hash to remain 64 bytes wide after the response.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientSmb311PreviewRejectsMalformedSmb311ResponsesMissingPreauthOrCarryingNoContexts",
                        displayName: "Client SMB 3.1.1 preview rejects malformed SMB 3.1.1 responses missing the preauth context or carrying no contexts at all",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession previewSession = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true
                            });
                            previewSession.CreateNegotiateRequest();

                            Smb2NegotiateResponse responseMissingContexts = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb311,
                                ServerGuid = Guid.NewGuid(),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536,
                                SystemTime = 0x01D811223344AA00UL,
                                ServerStartTime = 0x01D811223344BB00UL,
                                SecurityBuffer = Array.Empty<byte>()
                            };
                            TestAssertions.Throws<OpenCifsClientStateException>(
                                () => previewSession.ApplyNegotiateResponse(responseMissingContexts),
                                "Client should reject SMB 3.1.1 negotiate responses that carry no negotiate-context entries.");

                            OpenCifsClientSession previewSession2 = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true
                            });
                            previewSession2.CreateNegotiateRequest();

                            Smb2NegotiateResponse responseMissingPreauth = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb311,
                                ServerGuid = Guid.NewGuid(),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536,
                                SystemTime = 0x01D811223344AA00UL,
                                ServerStartTime = 0x01D811223344BB00UL,
                                SecurityBuffer = Array.Empty<byte>()
                            };
                            responseMissingPreauth.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry
                                {
                                    ContextType = Smb2NegotiateContextType.EncryptionCapabilities,
                                    Payload = new EncryptionCapabilities
                                    {
                                        Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes128Gcm }
                                    }.ToByteArray()
                                }
                            });
                            TestAssertions.Throws<OpenCifsClientStateException>(
                                () => previewSession2.ApplyNegotiateResponse(responseMissingPreauth),
                                "Client should reject SMB 3.1.1 negotiate responses that omit the mandatory preauth integrity context.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientSmb311PreviewIsToleratedByExistingServersThatNegotiateSmb302",
                        displayName: "Client SMB 3.1.1 preview is tolerated by existing servers and still negotiates SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession previewSession = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true,
                                PreferEncryption = false
                            });
                            Smb2NegotiateRequest previewRequest = previewSession.CreateNegotiateRequest();
                            TestAssertions.True(
                                Array.IndexOf(previewRequest.Dialects, SmbDialect.Smb311) >= 0,
                                "Preview client should advertise SMB 3.1.1.");

                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb302,
                                ServerGuid = Guid.NewGuid(),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                MaxTransactSize = 65536,
                                MaxReadSize = 65536,
                                MaxWriteSize = 65536,
                                SystemTime = 0x01D811223344AA00UL,
                                ServerStartTime = 0x01D811223344BB00UL,
                                SecurityBuffer = Array.Empty<byte>()
                            };
                            previewSession.ApplyNegotiateResponse(response);
                            TestAssertions.True(previewSession.NegotiatedDialect.HasValue, "Preview session should have a negotiated dialect after a successful response.");
                            TestAssertions.Equal(SmbDialect.Smb302, previewSession.NegotiatedDialect!.Value, "Preview client should accept SMB 3.0.2 selected by the existing tolerance path.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAppliesOptInSmb302NegotiationResponse",
                        displayName: "Client negotiate handling accepts an opt-in SMB 3.0.2 response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                PreferEncryption = false
                            });
                            session.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb302,
                                ServerGuid = Guid.NewGuid(),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 65536,
                                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302),
                                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb302)
                            };

                            session.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb302, session.NegotiatedDialect!.Value, "Expected the opt-in client session to negotiate SMB 3.0.2.");
                            TestAssertions.Equal(response.MaxReadSize, session.NegotiatedMaxReadSize, "Expected the opt-in client session to preserve the negotiated max read size.");
                            TestAssertions.True(session.IsSigningRequired, "Expected signing to remain required after SMB 3.0.2 negotiation.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Negotiate",
                        caseId: "ClientAppliesOptInSmb30NegotiationResponseWhenServerClamps",
                        displayName: "Client negotiate handling accepts an opt-in SMB 3.0 response when the server clamps below SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                PreferEncryption = false
                            });
                            session.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb30,
                                ServerGuid = Guid.NewGuid(),
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 65536,
                                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb30),
                                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(SmbDialect.Smb30)
                            };

                            session.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb30, session.NegotiatedDialect!.Value, "Expected the opt-in client session to negotiate SMB 3.0 when the server clamps below SMB 3.0.2.");
                            TestAssertions.Equal(response.MaxReadSize, session.NegotiatedMaxReadSize, "Expected the opt-in client session to preserve the negotiated SMB 3.0 max read size.");
                            TestAssertions.True(session.IsSigningRequired, "Expected signing to remain required after SMB 3.0 negotiation.");
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
                        caseId: "ClientSignsAuthenticatedPacketsWithAesCmacWhenNegotiatedSmb302",
                        displayName: "Client signs authenticated SMB2 packets with AES-CMAC when SMB 3.0.2 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            (OpenCifsServerHost host, OpenCifsClientSession session, ulong sessionId) = CreateAuthenticatedLoopbackPair(SmbDialect.Smb302);
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

                            (OpenCifsServerHost host, OpenCifsClientSession session, ulong sessionId) = CreateAuthenticatedLoopbackPair(SmbDialect.Smb30);
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

                                TestAssertions.Throws<OpenCifsClientProtocolException>(
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

                                TestAssertions.Throws<OpenCifsClientProtocolException>(
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

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
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
                            TestAssertions.Equal(Smb2HeaderFlags.RelatedOperations | Smb2HeaderFlags.Signed, closeHeader.Flags, "Expected authenticated related compounded requests to preserve SMB2 signing while marking the request as related.");

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

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
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
                        caseId: "ClientBuildsSmb302DurableHandleV2RequestsAndTracksReconnectState",
                        displayName: "Client builds SMB 3.0.2 durable-handle v2 requests and tracks reconnect state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient(SmbDialect.Smb302);
                            session.ApplyTreeConnectResult("public", 42, NtStatus.Success, CreateTreeConnectSuccessResponse());

                            Smb2CreateRequest createRequest = session.CreateCreateRequest(
                                42,
                                "shared.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Open,
                                requestedOplockLevel: Smb2OplockLevel.Batch,
                                requestDurableHandle: true);
                            Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(createRequest.CreateContexts);
                            TestAssertions.Equal(1, initialCreateContexts.Length, "Expected the bounded SMB 3.0.2 durable open to carry a single durable-handle v2 request context.");
                            TestAssertions.True(Smb2DurableHandleRequestV2Context.IsMatch(initialCreateContexts[0]), "Expected the bounded SMB 3.0.2 durable open to use the durable-handle v2 request context.");
                            Smb2DurableHandleRequestV2Context durableHandleRequestV2 = Smb2DurableHandleRequestV2Context.ReadFrom(initialCreateContexts[0]);
                            TestAssertions.False(durableHandleRequestV2.CreateGuid == Guid.Empty, "Expected the bounded SMB 3.0.2 durable-handle v2 request to generate a non-empty create GUID.");
                            TestAssertions.Equal(0U, durableHandleRequestV2.Timeout, "Expected the bounded SMB 3.0.2 durable-handle v2 request to use the managed default timeout request.");
                            TestAssertions.Equal(Smb2DurableHandleFlags.None, durableHandleRequestV2.Flags, "Expected the bounded SMB 3.0.2 durable-handle v2 request to stay non-persistent.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 900,
                                    VolatileFileId = 901,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleResponseV2Context
                                        {
                                            Timeout = 300000,
                                            Flags = Smb2DurableHandleFlags.None
                                        }.ToCreateContext()
                                    })
                                },
                                createRequest);
                            TestAssertions.True(openState.IsDurable, "Expected the bounded SMB 3.0.2 durable create result to be tracked as durable.");
                            TestAssertions.True(openState.UsesDurableHandleV2, "Expected the bounded SMB 3.0.2 durable create result to be tracked as durable-handle v2.");
                            TestAssertions.False(openState.DurableCreateGuid == Guid.Empty, "Expected the bounded SMB 3.0.2 durable create result to preserve the request create GUID.");
                            TestAssertions.Equal(300000U, openState.DurableTimeoutMs, "Expected the bounded SMB 3.0.2 durable create result to preserve the granted durable timeout.");
                            TestAssertions.False(openState.IsPersistent, "Expected the bounded SMB 3.0.2 durable create result to remain non-persistent.");

                            Smb2CreateRequest reconnectRequest = session.CreateDurableReconnectCreateRequest(
                                42,
                                "shared.txt",
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                requestedOplockLevel: Smb2OplockLevel.Batch,
                                durableCreateGuid: openState.DurableCreateGuid,
                                useDurableHandleV2: openState.UsesDurableHandleV2);
                            Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectRequest.CreateContexts);
                            TestAssertions.Equal(1, reconnectCreateContexts.Length, "Expected the bounded SMB 3.0.2 durable reconnect to carry a single durable-handle v2 reconnect context.");
                            TestAssertions.True(Smb2DurableHandleReconnectV2Context.IsMatch(reconnectCreateContexts[0]), "Expected the bounded SMB 3.0.2 durable reconnect to use the durable-handle v2 reconnect context.");
                            Smb2DurableHandleReconnectV2Context durableHandleReconnectV2 = Smb2DurableHandleReconnectV2Context.ReadFrom(reconnectCreateContexts[0]);
                            TestAssertions.Equal(openState.PersistentFileId, durableHandleReconnectV2.PersistentFileId, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the persistent file identifier.");
                            TestAssertions.Equal(openState.VolatileFileId, durableHandleReconnectV2.VolatileFileId, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the original volatile file identifier.");
                            TestAssertions.Equal(openState.DurableCreateGuid, durableHandleReconnectV2.CreateGuid, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the create GUID.");
                            TestAssertions.Equal(Smb2DurableHandleFlags.None, durableHandleReconnectV2.Flags, "Expected the bounded SMB 3.0.2 durable reconnect to stay non-persistent.");

                            OpenState reconnectedOpenState = session.ApplyCreateResult(
                                42,
                                "shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 900,
                                    VolatileFileId = 902,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleResponseV2Context
                                        {
                                            Timeout = 300000,
                                            Flags = Smb2DurableHandleFlags.None
                                        }.ToCreateContext()
                                    })
                                },
                                reconnectRequest);
                            TestAssertions.True(reconnectedOpenState.UsesDurableHandleV2, "Expected the bounded SMB 3.0.2 durable reconnect result to remain durable-handle v2.");
                            TestAssertions.Equal(openState.DurableCreateGuid, reconnectedOpenState.DurableCreateGuid, "Expected the bounded SMB 3.0.2 durable reconnect result to preserve the original create GUID.");
                            TestAssertions.Equal(300000U, reconnectedOpenState.DurableTimeoutMs, "Expected the bounded SMB 3.0.2 durable reconnect result to preserve the granted durable timeout.");
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

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
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
                            TestAssertions.Equal(OpenCifsErrorCategory.ProtocolError, queryInfoException.Category, "Expected query-info failure to normalize to ProtocolError.");

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
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, setInfoException.Category, "Expected set-info failure to normalize to AccessDenied.");
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
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ValidateOplockBreakNotificationPacket(Smb2CompoundPacket.ReadFrom(unsignedPacketBytes), unsignedPacketBytes),
                                "Expected signed sessions to reject unsigned oplock-break notifications.");

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
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
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

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
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
                        caseId: "ClientConnectionAdvancedSurfaceExposesTryAsyncResultEnvelopeCompanions",
                        displayName: "Client connection advanced surface exposes TryAsync result-envelope companions for lifecycle and raw SMB workflows",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            if (typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryConnectAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryConnectAndAuthenticateAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryTreeConnectAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryValidateSecureNegotiateAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryCompoundOpenReadCloseAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryOpenAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryReadAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryQueryDirectoryAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryChangeNotifyAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryCloseAsync)) == null ||
                                typeof(OpenCifsClientConnection).GetMethod(nameof(OpenCifsClientConnection.TryDisconnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected the advanced/raw client connection surface to expose bounded Try...Async result-envelope companions.");
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
                        caseId: "ClientConnectionAutoValidatesSecureNegotiateDuringEncryptedSmb302TreeConnect",
                        displayName: "Client connection auto-validates secure negotiate during encrypted SMB 3.0.2 tree connect and supports explicit revalidation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnectionSecureNegotiate_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                minimumDialect: SmbDialect.Smb302,
                                maximumDialect: SmbDialect.Smb302,
                                requireEncryptionForSmb3: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    PreferEncryption = true
                                });

                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.Equal(SmbDialect.Smb302, client.Session.NegotiatedDialect!.Value, "Expected the direct-TCP secure-negotiate test client to negotiate SMB 3.0.2.");
                                TestAssertions.False(client.Session.IsSecureNegotiateValidated, "Expected secure-negotiate validation to remain pending until the first tree connection completes.");

                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(client.Session.IsSecureNegotiateValidated, "Expected SMB 3.0.2 tree connect to complete bounded secure-negotiate validation automatically.");

                                await client.ValidateSecureNegotiateAsync(treeHandle, token).ConfigureAwait(false);
                                OpenCifsClientResult validationResult = await client.TryValidateSecureNegotiateAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.True(validationResult.IsSuccess, "Expected the non-throwing explicit secure-negotiate validation path to succeed after the automatic tree-connect validation.");

                                OpenCifsClientOpenHandle fileHandle = await client.OpenAsync(
                                    treeHandle,
                                    "secure.txt",
                                    desiredAccess: 0xC0010000U,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("secure-negotiate-data");
                                await client.WriteAsync(fileHandle, expectedBytes, 0, token).ConfigureAwait(false);
                                await client.FlushAsync(fileHandle, token).ConfigureAwait(false);
                                byte[] actualBytes = await client.ReadAsync(fileHandle, (uint)expectedBytes.Length, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the SMB 3.0.2 direct-TCP client to remain usable after automatic and explicit secure-negotiate validation.");

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
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsUnauthenticatedUseBadCredentialsAndStaleHandles",
                        displayName: "Client connection rejects unauthenticated use, bad credentials, and stale handles",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            await using OpenCifsClientConnection disconnectedClient = new OpenCifsClientConnection(new OpenCifsClientOptions());
                            await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                () => disconnectedClient.AuthenticateAsync(CreateCredential(), token),
                                "Expected authenticate to reject use before connect.");
                            await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
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
                                TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, authenticationException.Category, "Expected invalid credentials to normalize to AccessDenied.");
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

                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => client.ReadAsync(fileHandle, 1, 0, cancellationToken: token),
                                    "Expected closed open handles to be rejected.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
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
                        caseId: "ClientConnectionTryAsyncCompanionsReportPositiveAndNegativeAdvancedFlows",
                        displayName: "Client connection TryAsync companions report positive and negative advanced lifecycle and compound flows",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnectionTry_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            File.WriteAllText(Path.Combine(sharePath, "docs", "sample.txt"), "advanced-try-surface");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                OpenCifsClientResult connectAndAuthenticateResult = await client.TryConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(connectAndAuthenticateResult.IsSuccess, "Expected TryConnectAndAuthenticateAsync to succeed against the live listener.");

                                OpenCifsClientResult<OpenCifsClientTreeHandle> treeResult = await client.TryTreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(treeResult.IsSuccess, "Expected TryTreeConnectAsync to succeed for the public share.");
                                OpenCifsClientTreeHandle treeHandle = treeResult.GetValueOrThrow();

                                OpenCifsClientResult<byte[]> compoundReadResult = await client.TryCompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\sample.txt",
                                    64,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(compoundReadResult.IsSuccess, "Expected TryCompoundOpenReadCloseAsync to succeed for the existing file.");
                                TestAssertions.Equal("advanced-try-surface", System.Text.Encoding.UTF8.GetString(compoundReadResult.GetValueOrThrow()), "Expected the advanced/raw Try compound read to preserve the file payload.");

                                OpenCifsClientResult<byte[]> missingReadResult = await client.TryCompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\missing.txt",
                                    16,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(missingReadResult.IsSuccess, "Expected TryCompoundOpenReadCloseAsync to report a failure envelope for a missing file.");
                                TestAssertions.Equal(Smb2Command.Create, missingReadResult.Command, "Expected missing-file compound reads to surface the create leg.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadResult.Status, "Expected missing-file compound reads to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingReadResult.ErrorCategory, "Expected missing-file compound reads to normalize to NotFound.");

                                await TestAssertions.ThrowsAsync<ArgumentNullException>(
                                    () => client.TryOpenAsync(treeHandle: null!, path: "docs\\sample.txt", cancellationToken: token),
                                    "Expected advanced/raw Try wrappers to preserve local argument validation and not flatten it into a result envelope.");

                                OpenCifsClientResult disconnectResult = await client.TryDisconnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(disconnectResult.IsSuccess, "Expected TryDisconnectAsync to succeed after the live advanced/raw flow.");

                                OpenCifsClientResult<OpenCifsClientTreeHandle> postDisconnectTreeResult = await client.TryTreeConnectAsync("public", token).ConfigureAwait(false);
                                TestAssertions.False(postDisconnectTreeResult.IsSuccess, "Expected TryTreeConnectAsync to report a failure envelope after disconnect.");
                                TestAssertions.True(postDisconnectTreeResult.Exception is OpenCifsClientStateException, "Expected post-disconnect advanced/raw failures to preserve the typed client-state exception.");
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
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, shareAccessException.Category, "Expected the direct-TCP share-access failure to normalize to Conflict.");

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
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, lockException.Category, "Expected the conflicting byte-range lock to normalize to Conflict.");

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
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, deleteException.Category, "Expected non-empty directory delete rejection to normalize to Conflict.");
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
                                TestAssertions.True(durableOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 direct-TCP durable open to use durable-handle v2.");
                                TestAssertions.Equal(300000U, durableOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 direct-TCP durable open to preserve the bounded durable timeout.");
                                TestAssertions.False(durableOpen.IsPersistent, "Expected the default SMB 3.0.2 direct-TCP durable open to remain non-persistent.");

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
                                TestAssertions.True(reconnectedOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 direct-TCP durable reconnect to remain on durable-handle v2.");
                                TestAssertions.Equal(300000U, reconnectedOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 direct-TCP durable reconnect to preserve the bounded durable timeout.");
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
                        caseId: "ClientConnectionReconnectsDurableLeaseOpenAfterTransportDisconnect",
                        displayName: "Client connection reconnects a durable lease-backed open after an ungraceful transport disconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-client-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                byte[] leaseKey = Hex("0102030405060708090A0B0C0D0E0F10");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
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
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey).ConfigureAwait(false);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial direct-TCP lease-backed open to be granted durable reconnect state.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the initial direct-TCP durable lease open to expose a reconnect token.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, durableOpen.OplockLevel, "Expected the initial direct-TCP durable lease open to receive an SMB 2.1 lease.");
                                TestAssertions.SequenceEqual(leaseKey, durableOpen.LeaseKey, "Expected the direct-TCP durable lease open to preserve the requested lease key.");
                                TestAssertions.Equal(leaseState, durableOpen.LeaseState, "Expected the direct-TCP durable lease open to preserve the granted lease state.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                TestAssertions.False(client.IsConnected, "Expected transport simulation to tear down the active direct-TCP connection.");
                                TestAssertions.True(durableOpen.IsClosed, "Expected the original durable lease open handle to be retired from active use after transport loss.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the durable lease open handle to remain usable as a reconnect token after transport loss.");

                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await client.ReconnectDurableOpenAsync(secondTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable lease reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    durableOpen.VolatileFileId == reconnectedOpen.VolatileFileId,
                                    "Expected durable lease reconnect to allocate a new volatile file identifier.");
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP lease-backed open to remain durable.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, reconnectedOpen.OplockLevel, "Expected durable lease reconnect to preserve the lease-backed oplock level.");
                                TestAssertions.SequenceEqual(leaseKey, reconnectedOpen.LeaseKey, "Expected durable lease reconnect to preserve the original lease key.");
                                TestAssertions.Equal(leaseState, reconnectedOpen.LeaseState, "Expected durable lease reconnect to preserve the granted lease state.");
                                TestAssertions.False(durableOpen.CanReconnectDurably, "Expected the consumed durable lease reconnect token to be retired after success.");

                                byte[] actualBytes = await client.ReadAsync(reconnectedOpen, 32, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-lease-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected durable lease reconnect to preserve file access over the new session.");

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
                        caseId: "ClientConnectionReconnectsDurableLeaseOpenWithDowngradedLeaseStateWhenACompetingOpenExists",
                        displayName: "Client connection reconnects a durable lease-backed open with a downgraded lease state when a competing open exists",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-client-data");
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                byte[] leaseKey = Hex("1112131415161718191A1B1C1D1E1F20");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                await using OpenCifsClientConnection durableClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await using OpenCifsClientConnection competingClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
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
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey).ConfigureAwait(false);

                                await durableClient.SimulateTransportDisconnectAsync().ConfigureAwait(false);

                                await competingClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle competingTree = await competingClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle competingOpen = await competingClient.OpenAsync(
                                    competingTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle reconnectedTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await durableClient.ReconnectDurableOpenAsync(reconnectedTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP lease-backed open to remain durable.");
                                TestAssertions.SequenceEqual(leaseKey, reconnectedOpen.LeaseKey, "Expected the reconnected direct-TCP lease-backed open to preserve its lease key.");
                                TestAssertions.Equal(Smb2LeaseState.None, reconnectedOpen.LeaseState, "Expected the competing open to downgrade the reconnected durable lease state to none.");

                                byte[] actualBytes = await durableClient.ReadAsync(reconnectedOpen, 32, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-lease-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected the downgraded durable lease reconnect path to preserve file access.");

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
                                TestAssertions.True(durableOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 lock-carryover durable open to use durable-handle v2.");
                                TestAssertions.Equal(300000U, durableOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 lock-carryover durable open to preserve the bounded durable timeout.");
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
                                TestAssertions.True(reconnectedOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 lock-carryover durable reconnect to remain on durable-handle v2.");

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
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesRealisticCompoundCreateQueryReadWriteAndCloseFlows",
                        displayName: "Client connection completes realistic create-query-close, create-write-flush-close, and open-read-close compound flows over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("compound-connection-data");
                                uint writtenCount = await client.CompoundCreateWriteFlushCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    expectedBytes,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal((uint)expectedBytes.Length, writtenCount, "Expected the bounded compound write helper to acknowledge the full write length.");

                                FileAllInformation allInformation = FileAllInformation.ReadFrom(await client.CompoundCreateQueryInfoCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    FileInformationClass.AllInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.False(allInformation.StandardInformation.Directory, "Expected the bounded compound metadata helper to report a file.");
                                TestAssertions.Equal((ulong)expectedBytes.Length, allInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF after the bounded compound write helper.");
                                TestAssertions.Equal("docs\\compound.txt", allInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name after the bounded compound query helper.");

                                byte[] actualBytes = await client.CompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    checked((uint)expectedBytes.Length),
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the bounded compound read helper to round-trip the file payload.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected bounded compound helpers to avoid leaking tracked opens on the client session.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, File.ReadAllBytes(Path.Combine(sharePath, "docs", "compound.txt")), "Unexpected bytes persisted by the bounded compound helpers.");
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
                        caseId: "ClientConnectionCompoundHelpersPropagateCreateFailuresWithoutLeakingTrackedOpens",
                        displayName: "Client connection compound helpers propagate create failures and leave no tracked opens behind",
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
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                OpenCifsStatusException missingReadException;

                                try
                                {
                                    await client.CompoundOpenReadCloseAsync(treeHandle, "missing.txt", 8, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected compound open-read-close to fail for a missing path.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    missingReadException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, missingReadException.Command, "Expected missing-path compound reads to surface the create failure.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadException.Status, "Expected missing-path compound reads to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingReadException.Category, "Expected missing-path compound reads to normalize to NotFound.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected failed bounded compound reads not to leak tracked opens.");

                                OpenCifsStatusException missingQueryException;

                                try
                                {
                                    await client.CompoundCreateQueryInfoCloseAsync(treeHandle, "missing.txt", FileInformationClass.AllInformation, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected compound create-query-close to fail for a missing path.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    missingQueryException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, missingQueryException.Command, "Expected missing-path compound metadata queries to surface the create failure.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingQueryException.Status, "Expected missing-path compound metadata queries to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingQueryException.Category, "Expected missing-path compound metadata queries to normalize to NotFound.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected failed bounded compound metadata queries not to leak tracked opens.");

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
                });
        }

        /// <summary>
        /// Build the aligned primary client surface suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ClientPrimarySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Primary",
                displayName: "Client primary happy-path surface",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceBuildsImmutableSettingsAndExposesAlignedApis",
                        displayName: "Client primary surface builds immutable settings and exposes aligned builder, client, and share-session APIs",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSettings settings = new OpenCifsClientBuilder()
                                .WithServer("files.example.test", 1445)
                                .WithDialectRange(SmbDialect.Smb21, SmbDialect.Smb21)
                                .WithSigningRequired()
                                .WithPreferredEncryption(false)
                                .WithConnectTimeoutMs(12345)
                                .BuildSettings();

                            TestAssertions.Equal("files.example.test", settings.ServerName, "Unexpected immutable client settings server name.");
                            TestAssertions.Equal(1445, settings.ServerPort, "Unexpected immutable client settings port.");
                            TestAssertions.Equal(SmbDialect.Smb21, settings.MinimumDialect, "Unexpected immutable client settings minimum dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, settings.MaximumDialect, "Unexpected immutable client settings maximum dialect.");
                            TestAssertions.True(settings.RequireSigning, "Expected immutable client settings to preserve signing requirements.");
                            TestAssertions.False(settings.PreferEncryption, "Expected immutable client settings to preserve encryption preference overrides.");
                            TestAssertions.Equal(12345, settings.ConnectTimeoutMs, "Unexpected immutable client settings timeout.");

                            if (typeof(OpenCifsClientSettings).GetProperty(nameof(OpenCifsClientSettings.ServerName))?.CanWrite == true)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClientSettings to remain immutable.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.ConnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose ConnectAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryConnectAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryConnectAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.OpenShareAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose OpenShareAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryOpenShareAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryOpenShareAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.EnumerateSharesAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose EnumerateSharesAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryEnumerateSharesAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryEnumerateSharesAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.GetShareInfoAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose GetShareInfoAsync.");
                            }

                            if (typeof(OpenCifsClient).GetMethod(nameof(OpenCifsClient.TryGetShareInfoAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsClient to expose TryGetShareInfoAsync.");
                            }

                            if (typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Files)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Directories)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Metadata)) == null ||
                                typeof(OpenCifsShareSession).GetProperty(nameof(OpenCifsShareSession.Locks)) == null)
                            {
                                throw new InvalidOperationException("Expected OpenCifsShareSession to expose Files, Directories, Metadata, and Locks.");
                            }

                            if (typeof(OpenCifsShareFileOperations).GetMethod(nameof(OpenCifsShareFileOperations.TryReadAllBytesAsync)) == null ||
                                typeof(OpenCifsShareDirectoryOperations).GetMethod(nameof(OpenCifsShareDirectoryOperations.TryCreateAsync)) == null ||
                                typeof(OpenCifsShareMetadataOperations).GetMethod(nameof(OpenCifsShareMetadataOperations.TryGetAttributesAsync)) == null ||
                                typeof(OpenCifsShareLockOperations).GetMethod(nameof(OpenCifsShareLockOperations.TryAcquireExclusiveAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected grouped primary client operations to expose Try...Async result-envelope companions.");
                            }

                            if (typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.IsSuccess)) == null ||
                                typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.ErrorCategory)) == null ||
                                typeof(OpenCifsClientResult).GetProperty(nameof(OpenCifsClientResult.Status)) == null ||
                                typeof(OpenCifsClientResult<byte[]>).GetProperty(nameof(OpenCifsClientResult<byte[]>.Value)) == null)
                            {
                                throw new InvalidOperationException("Expected the primary client result-envelope types to expose success, category, status, and value members.");
                            }

                            OpenCifsPreviewAttribute? clientPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsClient), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;
                            OpenCifsPreviewAttribute? shareSessionPreview =
                                Attribute.GetCustomAttribute(typeof(OpenCifsShareSession), typeof(OpenCifsPreviewAttribute)) as OpenCifsPreviewAttribute;

                            if (clientPreview != null || shareSessionPreview != null)
                            {
                                throw new InvalidOperationException("Expected the aligned primary client surface to remain outside preview-only markers.");
                            }

                            await using OpenCifsClient client = new OpenCifsClientBuilder()
                                .WithServer("127.0.0.1", 4450)
                                .Build();
                            TestAssertions.Equal("127.0.0.1", client.Settings.ServerName, "Unexpected primary client server setting.");
                            TestAssertions.Equal(4450, client.Settings.ServerPort, "Unexpected primary client port setting.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySampleExistsAndUsesAlignedHighLevelSurface",
                        displayName: "Client primary sample exists and uses the aligned high-level surface without low-level primitives",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string samplePath = RepositoryPaths.FromRoot(Path.Combine("docs", "samples", "OpenCifsClientHappyPath.cs"));
                            string resultEnvelopeSamplePath = RepositoryPaths.FromRoot(Path.Combine("docs", "samples", "OpenCifsClientResultEnvelopeHappyPath.cs"));
                            FileAssertions.AssertExists(samplePath);
                            FileAssertions.AssertExists(resultEnvelopeSamplePath);
                            string sampleCode = File.ReadAllText(samplePath);
                            string resultEnvelopeSampleCode = File.ReadAllText(resultEnvelopeSamplePath);

                            if (!sampleCode.Contains("OpenCifsClientBuilder", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsClient", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsShareSession", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".OpenShareAsync(", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Files.", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Directories.", StringComparison.Ordinal) ||
                                !sampleCode.Contains(".Metadata.", StringComparison.Ordinal) ||
                                !sampleCode.Contains("OpenCifsStatusException", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated client happy-path sample to use the aligned builder -> client -> share-session surface.");
                            }

                            if (sampleCode.Contains("OpenCifsClientConnection", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientSession", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientTreeHandle", StringComparison.Ordinal) ||
                                sampleCode.Contains("OpenCifsClientOpenHandle", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated client happy-path sample to avoid low-level connection, session, tree, and open primitives.");
                            }

                            if (!resultEnvelopeSampleCode.Contains(".TryConnectAsync(", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains(".TryOpenShareAsync(", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains("OpenCifsClientResult", StringComparison.Ordinal) ||
                                !resultEnvelopeSampleCode.Contains("GetValueOrThrow", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the dedicated non-throwing client sample to use the primary Try...Async result-envelope surface.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceConnectsAndHandlesShareScopedPathFirstOperations",
                        displayName: "Client primary surface connects and handles share-scoped path-first file, directory, metadata, and lock operations",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimary_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await client.EchoAsync(token).ConfigureAwait(false);

                                await using OpenCifsShareSession share = await client.OpenShareAsync("public", token).ConfigureAwait(false);
                                await share.Directories.CreateAsync("/docs", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("primary-surface-network-data");
                                await share.Files.WriteAllBytesAsync("/docs/sample.txt", expectedBytes, token).ConfigureAwait(false);
                                byte[] actualBytes = await share.Files.ReadAllBytesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the primary client surface to round-trip the file payload.");

                                OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(checked((ulong)expectedBytes.Length), metadata.EndOfFile, "Unexpected primary client metadata EOF value.");

                                OpenCifsClientDirectoryEntry[] directoryEntries = await share.Directories.EnumerateAsync("/docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, directoryEntries.Length, "Expected the primary client surface to enumerate the created file.");
                                TestAssertions.Equal("sample.txt", directoryEntries[0].FileName, "Unexpected primary client directory entry name.");

                                OpenCifsShareFileLock shareLock = await share.Locks.AcquireExclusiveAsync("/docs/sample.txt", 0, 4, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(shareLock.IsReleased, "Expected the grouped lock surface to keep the file lock alive until release.");
                                await shareLock.ReleaseAsync(token).ConfigureAwait(false);
                                TestAssertions.True(shareLock.IsReleased, "Expected the grouped lock surface to report a released file lock after release.");

                                await share.Files.RenameAsync("/docs/sample.txt", "/docs/sample-renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                await share.Files.DeleteAsync("/docs/sample-renamed.txt", token).ConfigureAwait(false);
                                await share.Directories.DeleteAsync("/docs", token).ConfigureAwait(false);
                                await client.DisconnectAsync(token).ConfigureAwait(false);

                                string persistedPath = Path.Combine(sharePath, "docs", "sample-renamed.txt");
                                TestAssertions.False(File.Exists(persistedPath), "Expected the primary client surface to clean up the renamed file.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceTryApisReturnResultEnvelopesAcrossSuccessAndFailureFlows",
                        displayName: "Client primary surface Try APIs return result envelopes across success and failure flows",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryTry_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                OpenCifsClientResult connectResult = await client.TryConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(connectResult.IsSuccess, "Expected TryConnectAsync to succeed against the live listener.");

                                OpenCifsClientResult echoResult = await client.TryEchoAsync(token).ConfigureAwait(false);
                                TestAssertions.True(echoResult.IsSuccess, "Expected TryEchoAsync to succeed on the authenticated primary client surface.");

                                OpenCifsClientResult<OpenCifsShareSession> shareResult = await client.TryOpenShareAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(shareResult.IsSuccess, "Expected TryOpenShareAsync to succeed for the public share.");

                                await using OpenCifsShareSession share = shareResult.GetValueOrThrow();
                                OpenCifsClientResult createDirectoryResult = await share.Directories.TryCreateAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.True(createDirectoryResult.IsSuccess, "Expected TryCreateAsync to succeed for a new directory.");

                                await TestAssertions.ThrowsAsync<ArgumentException>(
                                    () => share.Metadata.TrySetBasicInfoAsync("/docs", cancellationToken: token),
                                    "Expected TrySetBasicInfoAsync to preserve local argument-validation failures instead of flattening them into a result envelope.").ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("result-envelope-network-data");
                                OpenCifsClientResult writeResult = await share.Files.TryWriteAllBytesAsync("/docs/sample.txt", expectedBytes, token).ConfigureAwait(false);
                                TestAssertions.True(writeResult.IsSuccess, "Expected TryWriteAllBytesAsync to succeed for the sample file.");

                                OpenCifsClientResult<byte[]> readResult = await share.Files.TryReadAllBytesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True(readResult.IsSuccess, "Expected TryReadAllBytesAsync to succeed for the sample file.");
                                TestAssertions.SequenceEqual(expectedBytes, readResult.GetValueOrThrow(), "Expected the TryReadAllBytesAsync envelope to preserve the file payload.");

                                OpenCifsClientResult<OpenCifsClientFileMetadata> metadataResult = await share.Metadata.TryGetAttributesAsync("/docs/sample.txt", token).ConfigureAwait(false);
                                TestAssertions.True(metadataResult.IsSuccess, "Expected TryGetAttributesAsync to succeed for the sample file.");
                                TestAssertions.Equal(checked((ulong)expectedBytes.Length), metadataResult.GetValueOrThrow().EndOfFile, "Unexpected TryGetAttributesAsync EOF value.");

                                OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> enumerateResult = await share.Directories.TryEnumerateAsync("/docs", "*.txt", token).ConfigureAwait(false);
                                TestAssertions.True(enumerateResult.IsSuccess, "Expected TryEnumerateAsync to succeed for the sample directory.");
                                TestAssertions.Equal(1, enumerateResult.GetValueOrThrow().Length, "Expected the TryEnumerateAsync envelope to return the created file.");

                                OpenCifsClientResult<OpenCifsShareFileLock> lockResult = await share.Locks.TryAcquireExclusiveAsync("/docs/sample.txt", 0, 4, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(lockResult.IsSuccess, "Expected TryAcquireExclusiveAsync to succeed for the sample file.");
                                OpenCifsShareFileLock shareLock = lockResult.GetValueOrThrow();
                                TestAssertions.False(shareLock.IsReleased, "Expected the TryAcquireExclusiveAsync envelope to return a live file lock.");
                                await shareLock.ReleaseAsync(token).ConfigureAwait(false);

                                OpenCifsClientResult missingFileResult = await share.Files.TryReadAllBytesAsync("/docs/missing.txt", token).ConfigureAwait(false);
                                TestAssertions.False(missingFileResult.IsSuccess, "Expected TryReadAllBytesAsync to report a failure envelope for a missing file.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingFileResult.ErrorCategory!.Value, "Expected missing-file read failures to preserve the normalized NotFound category.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingFileResult.Status!.Value, "Expected missing-file read failures to preserve the server NTSTATUS.");
                                TestAssertions.Equal(Smb2Command.Create, missingFileResult.Command!.Value, "Expected missing-file read failures to preserve the failing SMB2 command.");

                                OpenCifsClientResult wrongDeleteResult = await share.Directories.TryDeleteAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.False(wrongDeleteResult.IsSuccess, "Expected TryDeleteAsync to return a failure envelope for a non-empty directory.");
                                TestAssertions.Equal(OpenCifsErrorCategory.Conflict, wrongDeleteResult.ErrorCategory!.Value, "Expected non-empty directory delete failures to map to Conflict.");
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, wrongDeleteResult.Status!.Value, "Expected non-empty directory delete failures to preserve STATUS_DIRECTORY_NOT_EMPTY.");
                                TestAssertions.True(wrongDeleteResult.Exception is OpenCifsStatusException, "Expected non-empty directory delete failures to retain the typed SMB status exception.");
                                TestAssertions.True(wrongDeleteResult.ErrorData.Length == 0, "Expected bounded directory delete failures to expose empty SMB2 error-data bytes.");

                                OpenCifsClientResult renameResult = await share.Files.TryRenameAsync("/docs/sample.txt", "/docs/sample-renamed.txt", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(renameResult.IsSuccess, "Expected TryRenameAsync to succeed for the sample file.");

                                OpenCifsClientResult deleteFileResult = await share.Files.TryDeleteAsync("/docs/sample-renamed.txt", token).ConfigureAwait(false);
                                TestAssertions.True(deleteFileResult.IsSuccess, "Expected TryDeleteAsync to succeed for the renamed file.");

                                OpenCifsClientResult deleteDirectoryResult = await share.Directories.TryDeleteAsync("/docs", token).ConfigureAwait(false);
                                TestAssertions.True(deleteDirectoryResult.IsSuccess, "Expected TryDeleteAsync to succeed for the now-empty directory.");

                                OpenCifsClientResult disconnectResult = await client.TryDisconnectAsync(token).ConfigureAwait(false);
                                TestAssertions.True(disconnectResult.IsSuccess, "Expected TryDisconnectAsync to succeed after the primary result-envelope flow.");

                                OpenCifsClientResult postDisconnectCreateResult = await share.Directories.TryCreateAsync("/after-disconnect", token).ConfigureAwait(false);
                                TestAssertions.False(postDisconnectCreateResult.IsSuccess, "Expected TryCreateAsync to report a state failure after disconnect.");
                                TestAssertions.True(postDisconnectCreateResult.Exception is OpenCifsClientStateException, "Expected post-disconnect share-session failures to preserve the typed client-state exception.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceEnumeratesManagedSharesThroughOpenCifsIpcAndSrvsvc",
                        displayName: "Client primary surface enumerates managed shares through OpenCIFS IPC$ and srvsvc",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryBrowse_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(token).ConfigureAwait(false);
                                TestAssertions.True(sharesResult.IsSuccess, "Expected share browsing to succeed when the managed server explicitly registers the bounded IPC$/srvsvc endpoint.");

                                OpenCifsRemoteShareInfo[] shares = sharesResult.Value!;
                                TestAssertions.Equal(2, shares.Length, "Expected the bounded managed share-browse slice to expose the public data share and IPC$.");
                                TestAssertions.True(shares.Any(share => string.Equals(share.Name, "public", StringComparison.OrdinalIgnoreCase)), "Expected the bounded managed share-browse slice to include the public data share.");
                                TestAssertions.True(shares.Any(share => string.Equals(share.Name, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected the bounded managed share-browse slice to include IPC$ for named-pipe transport.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceShareBrowsingReportsMissingIpcSupportCleanly",
                        displayName: "Client primary surface share browsing reports a typed failure when the remote server does not expose IPC$",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryBrowse_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(token).ConfigureAwait(false);
                                TestAssertions.False(sharesResult.IsSuccess, "Expected share browsing to fail when the managed test listener omits the bounded IPC$/srvsvc endpoint registration.");
                                TestAssertions.True(sharesResult.Exception is OpenCifsStatusException, "Expected missing IPC$ support to surface as a typed SMB status exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, sharesResult.ErrorCategory!.Value, "Expected missing IPC$ support to normalize to NotFound.");
                                TestAssertions.Equal(Smb2Command.TreeConnect, sharesResult.Command!.Value, "Expected missing IPC$ support to fail during the IPC$ tree connect.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, sharesResult.Status!.Value, "Expected the missing IPC$ tree connect to preserve STATUS_OBJECT_NAME_NOT_FOUND when the managed listener does not register IPC$.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceTransceivesManagedNamedPipeThroughIpc",
                        displayName: "Client primary surface transceives a managed named pipe through IPC$",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryPipe_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true,
                                enableUtf8EchoPipe: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                byte[] requestBytes = System.Text.Encoding.UTF8.GetBytes("hello pipe");
                                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(
                                    OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName,
                                    requestBytes,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True(transceiveResult.IsSuccess, "Expected the bounded managed named-pipe echo endpoint to transceive successfully through IPC$.");
                                TestAssertions.SequenceEqual(requestBytes, transceiveResult.Value!, "Expected the bounded managed UTF-8 echo endpoint to return the original payload bytes.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceQueriesManagedShareInfoThroughOpenCifsIpcAndSrvsvc",
                        displayName: "Client primary surface queries managed share info through OpenCIFS IPC$ and srvsvc",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryShareInfo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync("public", token).ConfigureAwait(false);
                                TestAssertions.True(shareInfoResult.IsSuccess, "Expected bounded SRVSVC share-info queries to succeed when the managed server explicitly registers the bounded IPC$/srvsvc endpoint.");

                                OpenCifsRemoteShareInfo shareInfo = shareInfoResult.Value!;
                                TestAssertions.Equal("public", shareInfo.Name, "Unexpected managed SRVSVC share-info name.");
                                TestAssertions.Equal("disk", shareInfo.Kind, "Unexpected managed SRVSVC share-info kind.");
                                TestAssertions.True(shareInfo.HasDetailedInformation, "Expected bounded SRVSVC share-info queries to populate detailed fields.");
                                TestAssertions.Equal((uint)0, shareInfo.Permissions!.Value, "Unexpected managed SRVSVC share-info permissions.");
                                TestAssertions.Equal(UInt32.MaxValue, shareInfo.MaximumUses!.Value, "Unexpected managed SRVSVC share-info maximum-use value.");
                                TestAssertions.Equal((uint)0, shareInfo.CurrentUses!.Value, "Unexpected managed SRVSVC share-info current-use value.");
                                TestAssertions.Equal(sharePath, shareInfo.LocalPath, "Unexpected managed SRVSVC share-info local path.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceShareInfoReportsMissingShareCleanly",
                        displayName: "Client primary surface share info reports a typed failure when the target share is missing",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryShareInfo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync("missing", token).ConfigureAwait(false);
                                TestAssertions.False(shareInfoResult.IsSuccess, "Expected bounded SRVSVC share-info queries to fail when the target share is missing.");
                                TestAssertions.True(shareInfoResult.Exception is OpenCifsClientRpcException, "Expected bounded SRVSVC share-info missing-share failures to surface as a typed RPC exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, shareInfoResult.ErrorCategory!.Value, "Expected bounded SRVSVC share-info missing-share failures to normalize to NotFound.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceNamedPipeTransceiveReportsMissingPipeCleanly",
                        displayName: "Client primary surface named-pipe transceive reports a typed failure when the target pipe is missing",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryPipe_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableShareBrowsing: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(
                                    OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName,
                                    System.Text.Encoding.UTF8.GetBytes("missing"),
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(transceiveResult.IsSuccess, "Expected the bounded named-pipe transceive slice to fail when the requested pipe endpoint is not registered.");
                                TestAssertions.True(transceiveResult.Exception is OpenCifsStatusException, "Expected missing named-pipe endpoints to surface as a typed SMB status exception.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, transceiveResult.ErrorCategory!.Value, "Expected missing named-pipe endpoints to normalize to NotFound.");
                                TestAssertions.Equal(Smb2Command.Create, transceiveResult.Command!.Value, "Expected missing named-pipe endpoint failures to occur during the pipe create request.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, transceiveResult.Status!.Value, "Expected the missing named-pipe endpoint failure to preserve STATUS_OBJECT_NAME_NOT_FOUND.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceSmb311PreviewIsToleratedByLiveListenerAndCompletesAuthenticatedSession",
                        displayName: "Client primary surface SMB 3.1.1 preview is tolerated by a live listener and completes an authenticated session via SMB 3.0.2 fallback",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimarySmb311Preview_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithSmb311Preview()
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("smb311preview.txt", new byte[] { 0x53, 0x4D, 0x42, 0x33 }, token).ConfigureAwait(false);
                                byte[] payload = await share.Files.ReadAllBytesAsync("smb311preview.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(new byte[] { 0x53, 0x4D, 0x42, 0x33 }, payload, "Expected SMB 3.1.1 preview client to complete a write+read round trip against an existing tolerance server.");
                                await client.DisconnectAsync(token).ConfigureAwait(false);
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceSmb311PreviewBothSidesOptedInNegotiatesSmb311AndCompletesAuthenticatedSession",
                        displayName: "Client primary surface SMB 3.1.1 preview with both client and server opted in negotiates SMB 3.1.1 and completes an authenticated session under the derived SMB 3.1.1 keys",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimarySmb311BothSides_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                enableSmb311Preview: true).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithSmb311Preview()
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                TestAssertions.True(client.Session.NegotiatedDialect.HasValue, "Expected an authenticated SMB 3.1.1 preview session to have a negotiated dialect.");
                                TestAssertions.Equal(SmbDialect.Smb311, client.Session.NegotiatedDialect!.Value, "Expected both-sides-opted-in SMB 3.1.1 preview to actually negotiate the SMB 3.1.1 dialect end-to-end.");
                                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("smb311preview-bothsides.txt", new byte[] { 0x42, 0x4F, 0x54, 0x48 }, token).ConfigureAwait(false);
                                byte[] payload = await share.Files.ReadAllBytesAsync("smb311preview-bothsides.txt", token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(new byte[] { 0x42, 0x4F, 0x54, 0x48 }, payload, "Expected SMB 3.1.1 preview client+server to complete an encrypted write+read round trip under negotiated SMB 3.1.1.");
                                await client.DisconnectAsync(token).ConfigureAwait(false);
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceResolvesBoundedDfsReferralWithCacheReuse",
                        displayName: "Client primary surface resolves a bounded DFS referral and reuses the resolved cache entry",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimaryDfs_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                NamespacePath = "/team",
                                TargetServerName = "files-target",
                                TargetShareName = "data",
                                TargetPath = "/team",
                                TimeToLiveSeconds = 600
                            };
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                sharePath,
                                port,
                                token,
                                dfsReferral: referral).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);

                                string dfsPath = $"\\\\{TestEnvironmentDefaults.DefaultServerName}\\{TestEnvironmentDefaults.DefaultShareName}\\team\\report.txt";
                                OpenCifsResolvedDfsPath firstResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.False(firstResolution.WasResolvedFromCache, "Expected the first DFS resolution to come from a remote referral query.");
                                TestAssertions.Equal("files-target", firstResolution.TargetServerName, "Unexpected resolved DFS target server name.");
                                TestAssertions.Equal("data", firstResolution.TargetShareName, "Unexpected resolved DFS target share name.");
                                TestAssertions.True(firstResolution.TargetUncPath.EndsWith("report.txt", StringComparison.OrdinalIgnoreCase), "Expected the resolved DFS UNC path to preserve the unresolved suffix.");

                                OpenCifsResolvedDfsPath secondResolution = await client.ResolveDfsPathAsync(dfsPath, token).ConfigureAwait(false);
                                TestAssertions.True(secondResolution.WasResolvedFromCache, "Expected the second DFS resolution to be served from the client referral cache.");
                                TestAssertions.Equal(firstResolution.TargetUncPath, secondResolution.TargetUncPath, "Expected cached DFS resolutions to preserve the resolved target UNC path.");
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
                        suiteId: "Client.Primary",
                        caseId: "ClientPrimarySurfaceRejectsShareSessionUseAfterDisconnect",
                        displayName: "Client primary surface rejects share-session use after the parent client disconnects",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientPrimary_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

                            try
                            {
                                await using OpenCifsClient client = new OpenCifsClientBuilder()
                                    .WithServer("127.0.0.1", port)
                                    .Build();
                                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await using OpenCifsShareSession share = await client.OpenShareAsync("public", token).ConfigureAwait(false);
                                await client.DisconnectAsync(token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => share.Directories.CreateAsync("/docs", token),
                                    "Expected the primary share session to reject path-first operations after the parent client disconnects.").ConfigureAwait(false);
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
                        displayName: "Client builds secure-negotiate, open, and wildcard SMB2 IOCTL requests and accepts successful responses",
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

                            OpenCifsClientSession secureNegotiateSession = CreateAuthenticatedClient(SmbDialect.Smb302);
                            Smb2IoctlRequest validateNegotiateRequest = secureNegotiateSession.CreateValidateNegotiateInfoRequest(maxOutputResponse: 256);
                            ValidateNegotiateInfoRequest parsedValidateRequest = ValidateNegotiateInfoRequest.ReadFrom(validateNegotiateRequest.InputBuffer);
                            TestAssertions.Equal((uint)FsctlCode.ValidateNegotiateInfo, validateNegotiateRequest.CtlCode, "Unexpected secure-negotiate FSCTL code.");
                            TestAssertions.Equal(UInt64.MaxValue, validateNegotiateRequest.PersistentFileId, "Expected secure-negotiate requests to use the wildcard persistent file identifier.");
                            TestAssertions.Equal(UInt64.MaxValue, validateNegotiateRequest.VolatileFileId, "Expected secure-negotiate requests to use the wildcard volatile file identifier.");
                            TestAssertions.Equal(4, parsedValidateRequest.Dialects.Length, "Expected the secure-negotiate request to preserve the original offered dialect list.");
                            TestAssertions.Equal(SmbDialect.Smb302, parsedValidateRequest.Dialects[3], "Expected the secure-negotiate request to preserve SMB 3.0.2 in the offered dialect list.");
                            TestAssertions.Equal(secureNegotiateSession.ClientGuid, parsedValidateRequest.ClientGuid, "Expected the secure-negotiate request to preserve the original client GUID.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                parsedValidateRequest.Capabilities,
                                "Expected the secure-negotiate request to preserve the original client capability advertisement.");

                            ValidateNegotiateInfoResponse validateNegotiateResponse = secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new ValidateNegotiateInfoResponse
                                    {
                                        Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                        ServerGuid = secureNegotiateSession.ServerGuid!.Value,
                                        SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                        Dialect = SmbDialect.Smb302
                                    }.ToByteArray(),
                                    Flags = 0
                                });
                            TestAssertions.True(secureNegotiateSession.IsSecureNegotiateValidated, "Expected successful secure-negotiate validation to mark the authenticated SMB3 session as validated.");
                            TestAssertions.Equal(SmbDialect.Smb302, validateNegotiateResponse.Dialect, "Expected secure-negotiate validation to preserve the negotiated SMB3 dialect.");

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
                        displayName: "Client rejects invalid secure-negotiate, unknown-open, and failed SMB2 IOCTL responses",
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

                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateValidateNegotiateInfoRequest(),
                                "Secure-negotiate IOCTL requests should require an authenticated session.");

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

                            OpenCifsClientSession secureNegotiateSession = CreateAuthenticatedClient(SmbDialect.Smb302);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new ValidateNegotiateInfoResponse
                                        {
                                            Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                            ServerGuid = Guid.Parse("8FCA17D4-78F4-4967-8686-2C278149C391"),
                                            SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                            Dialect = SmbDialect.Smb302
                                        }.ToByteArray(),
                                        Flags = 0
                                    }),
                                "Secure-negotiate results should reject a mismatched server GUID.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new byte[] { 0x01 },
                                        Flags = 0
                                    }),
                                "Secure-negotiate results should reject unexpected FSCTL codes.");
                            return Task.CompletedTask;
                        })
                });
        }

        private static OpenCifsClientSession CreateNegotiatedClient(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER",
                PreferEncryption = dialect < SmbDialect.Smb30
            });
            session.CreateNegotiateRequest();
            Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None;

            if (dialect >= SmbDialect.Smb21)
            {
                capabilities |= Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing;
            }

            if (dialect >= SmbDialect.Smb30)
            {
                capabilities |= Smb2GlobalCapabilities.Encryption;
            }

            session.ApplyNegotiateResponse(new Smb2NegotiateResponse
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                Dialect = dialect,
                ServerGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f"),
                MaxTransactSize = 65536,
                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect),
                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect),
                Capabilities = capabilities
            });
            return session;
        }

        private static OpenCifsClientSession CreateAuthenticatedClient(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsClientSession session = CreateNegotiatedClient(dialect);
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

        private static (OpenCifsServerHost Host, OpenCifsClientSession Client, ulong SessionId) CreateAuthenticatedLoopbackPair(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsServerHost host = CreateLoopbackServerHost(dialect);
            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER",
                MaximumDialect = dialect,
                PreferEncryption = dialect < SmbDialect.Smb30
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

        private static OpenCifsServerHost CreateLoopbackServerHost(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
            {
                ServerName = TestEnvironmentDefaults.DefaultServerName,
                MaximumDialect = dialect,
                RequireEncryptionForSmb3 = dialect < SmbDialect.Smb30
            });
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = "SampleShare",
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });
            return builder.BuildHost();
        }

        private static OpenCifsClientCredential CreateCredential()
        {
            return new OpenCifsClientCredential
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            };
        }

        private static Smb2SessionSetupResponse CreateChallengeResponse(string serverName, string userDomain, byte[] serverChallenge)
        {
            LittleEndianWriter timestampWriter = new LittleEndianWriter();
            timestampWriter.WriteUInt64(DeterministicTestClock.GetFileTimeUtc("ClientTestSuites.CreateChallengeResponse"));

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

        private static Smb2SessionSetupResponse CreateSessionSetupSuccessResponse(Smb2SessionFlags sessionFlags = Smb2SessionFlags.None)
        {
            return new Smb2SessionSetupResponse
            {
                SessionFlags = sessionFlags,
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

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(
            string sharePath,
            int port,
            CancellationToken cancellationToken,
            int maximumCredits = 64,
            SmbDialect? minimumDialect = null,
            SmbDialect? maximumDialect = null,
            bool? requireEncryptionForSmb3 = null,
            bool enableShareBrowsing = false,
            bool enableUtf8EchoPipe = false,
            OpenCifsServerDfsReferral? dfsReferral = null,
            bool enableSmb311Preview = false)
        {
            DirectTcpPortReservation reservation = GetDirectTcpPortReservation(port);
            OpenCifsServerOptions options = new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = port,
                MaximumCredits = maximumCredits
            };

            if (minimumDialect.HasValue)
            {
                options.MinimumDialect = minimumDialect.Value;
            }

            if (maximumDialect.HasValue)
            {
                options.MaximumDialect = maximumDialect.Value;
            }

            if (requireEncryptionForSmb3.HasValue)
            {
                options.RequireEncryptionForSmb3 = requireEncryptionForSmb3.Value;
            }

            options.EnableSmb311Preview = enableSmb311Preview;

            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(options);
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = sharePath,
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });

            if (enableShareBrowsing)
            {
                builder.AddSrvsvcShareEnumerationEndpoint();
            }

            if (enableUtf8EchoPipe)
            {
                builder.AddUtf8EchoNamedPipeEndpoint();
            }

            if (dfsReferral != null)
            {
                builder.AddDfsReferral(dfsReferral);
            }

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


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
    internal static class ClientNegotiationSuiteBuilder
    {
        /// <summary>
        /// Build the client negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
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
    }
}

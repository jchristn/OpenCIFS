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
    internal static class ServerNegotiationSmb311RequestAndPreviewCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerAcceptsSmb311StyleNegotiateAndClampsToSmb302",
                        displayName: "Direct-TCP server accepts an SMB 3.1.1-style negotiate request shape and clamps selection to SMB 3.0.2",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: false,
                                token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb2NegotiateRequest request = new Smb2NegotiateRequest
                                {
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                    ClientGuid = Guid.NewGuid(),
                                    Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 },
                                    NegotiateContextCount = 1,
                                    NegotiateContextData = new byte[]
                                    {
                                        0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                    }
                                };
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2),
                                            request.ToByteArray())
                                    });

                                await WriteDirectTcpFrameAsync(stream, requestPacket.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the SMB 3.1.1-style request shape to clamp to the highest implemented SMB 3.0.2 dialect.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerNegotiatesRequiredEncryptionSmb302ForSmb311StyleRequestShape",
                        displayName: "Server negotiate handling accepts an SMB 3.1.1-style request shape for required-encryption SMB 3.0.2 negotiation",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = new byte[]
                                {
                                    0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the required-encryption server to accept the SMB 3.1.1-style request shape and negotiate SMB 3.0.2.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewCapturesNetnameContextAndExposesItForInspection",
                        displayName: "Server SMB 3.1.1 preview captures the client NETNAME context and exposes it for inspection",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x01, 0x02 }
                            }.ToByteArray();
                            byte[] netnamePayload = new NetnameNegotiateContext
                            {
                                ServerName = "files.contoso.test"
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });
                            TestAssertions.True(previewHost.GetReceivedClientNetname() == null, "Expected the host to start with no captured NETNAME.");

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("FEDCBA98-7654-3210-FEDC-BA9876543210"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.Netname, Payload = netnamePayload }
                            });

                            previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal("files.contoso.test", previewHost.GetReceivedClientNetname()!, "Expected the SMB 3.1.1 preview server to capture the client-supplied NETNAME server name for inspection.");

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = false,
                                RequireEncryptionForSmb3 = false
                            });
                            defaultHost.HandleNegotiate(previewRequest);
                            TestAssertions.True(defaultHost.GetReceivedClientNetname() == null, "Expected the default opt-out server to leave the captured NETNAME empty.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewEmitsTypedResponseContextsAndPreservesPreauthSelectionOnSmb311DialectMatch",
                        displayName: "Server SMB 3.1.1 preview emits typed Preauth and Encryption response contexts and preserves the selected algorithms when negotiating SMB 3.1.1",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xC0, 0xDE, 0xCA, 0xFE }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray();
                            byte[] signingPayload = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[]
                                {
                                    SigningAlgorithmId.AesGmac,
                                    SigningAlgorithmId.AesCmac,
                                    SigningAlgorithmId.HmacSha256
                                }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("ABCDEF01-2345-6789-ABCD-EF0123456789"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb311, previewResponse.Dialect, "Expected the preview server to negotiate SMB 3.1.1.");
                            TestAssertions.Equal((ushort)3, previewResponse.NegotiateContextCount, "Expected the preview server response to carry three typed negotiate-context entries.");

                            Smb2NegotiateContextEntry[] decodedResponseEntries = previewResponse.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(3, decodedResponseEntries.Length, "Expected three decoded response negotiate-context entries.");

                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedResponseEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Server should select SHA-512 preauth integrity in the response.");
                            TestAssertions.Equal(32, decodedPreauth.Salt.Length, "Server should generate a 32-byte preauth response salt.");

                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedResponseEntries[1].Payload);
                            TestAssertions.Equal(1, decodedEncryption.Ciphers.Length, "Server should select a single cipher in the response.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, decodedEncryption.Ciphers[0], "Server should prefer AES-128-GCM as the bounded cipher when offered.");

                            SigningCapabilities decodedSigning = SigningCapabilities.ReadFrom(decodedResponseEntries[2].Payload);
                            TestAssertions.Equal(1, decodedSigning.SigningAlgorithms.Length, "Server should select a single signing algorithm in the response.");
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, decodedSigning.SigningAlgorithms[0], "Server should select AES-GMAC as the bounded signing algorithm when offered.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewNegotiatesSmb311WhenBothOptInAndFallsBackToSmb302WhenMissingServerOptIn",
                        displayName: "Server SMB 3.1.1 preview negotiates SMB 3.1.1 when both sides opt in and falls back to SMB 3.0.2 when the server is missing the opt-in",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x10, 0x20, 0x30, 0x40 }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("11223344-5566-7788-99AA-BBCCDDEEFF00"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb311, previewResponse.Dialect, "Expected the preview-opted-in server to select SMB 3.1.1 when the client also opts in.");

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = false,
                                RequireEncryptionForSmb3 = false
                            });
                            Smb2NegotiateResponse defaultResponse = defaultHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb302, defaultResponse.Dialect, "Expected the default opt-out server to keep tolerance behavior and select SMB 3.0.2 against a 3.1.1 preview client.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewAccumulatesPreauthIntegrityTranscriptAcrossNegotiate",
                        displayName: "Server SMB 3.1.1 preview accumulates the preauth integrity transcript across the negotiate request and response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            defaultHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 }
                            });
                            byte[]? defaultHash = defaultHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(defaultHash == null, "Expected the default opt-out server to leave the preauth hash unallocated.");

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true,
                                EnableSmb311Preview = true
                            });
                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.Parse("E0A4B6F8-1234-4567-89AB-CDEF01234567"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            byte[]? initialHash = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(initialHash != null, "Expected the preview opt-in server to allocate the preauth hash accumulator after a 3.1.1-shaped request.");
                            TestAssertions.Equal(64, initialHash!.Length, "Expected the SHA-512 preauth hash to be 64 bytes wide.");

                            byte[] zeros = new byte[64];
                            TestAssertions.SequenceEqual(zeros, initialHash, "Expected the server preauth hash to start at all zeros per MS-SMB2.");

                            Smb2Header requestHeader = new Smb2Header
                            {
                                Command = Smb2Command.Negotiate,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.None,
                                MessageId = 0,
                                Signature = new byte[16]
                            };
                            previewHost.AppendPreauthMessageBytes(requestHeader, previewRequest.ToByteArray());
                            byte[]? afterRequest = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterRequest != null && !afterRequest.AsSpan().SequenceEqual(zeros), "Expected the server preauth hash to advance after appending the negotiate request.");

                            Smb2Header responseHeader = new Smb2Header
                            {
                                Command = Smb2Command.Negotiate,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                MessageId = requestHeader.MessageId,
                                Signature = new byte[16]
                            };
                            previewHost.AppendPreauthMessageBytes(responseHeader, previewResponse.ToByteArray());
                            byte[]? afterResponse = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterResponse != null && !afterResponse.AsSpan().SequenceEqual(afterRequest!), "Expected the server preauth hash to advance again after appending the negotiate response.");
                            TestAssertions.Equal(64, afterResponse!.Length, "Expected the server preauth hash to remain 64 bytes wide after the response.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerAcceptsTypedSmb311NegotiateContextRequestAndPreservesEntriesAfterWireRoundTrip",
                        displayName: "Server accepts a typed SMB 3.1.1 negotiate-context request and preserves typed entries after a wire round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray();
                            byte[] netnamePayload = new NetnameNegotiateContext
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName
                            }.ToByteArray();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            Smb2NegotiateRequest typedRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.Parse("E0A4B6F8-1234-4567-89AB-CDEF01234567"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            typedRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.Netname, Payload = netnamePayload }
                            });

                            byte[] wireBytes = typedRequest.ToByteArray();
                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(wireBytes);
                            TestAssertions.Equal((ushort)3, parsedRequest.NegotiateContextCount, "Wire round-trip should preserve negotiate-context count.");
                            Smb2NegotiateContextEntry[] decodedEntries = parsedRequest.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(3, decodedEntries.Length, "Wire round-trip should preserve negotiate-context entry count.");

                            Smb2NegotiateResponse response = host.HandleNegotiate(parsedRequest);
                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the server to negotiate SMB 3.0.2 against a typed SMB 3.1.1 negotiate-context request shape.");

                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip through the server's negotiate-context tolerance.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip through the server's negotiate-context tolerance.");
                            NetnameNegotiateContext decodedNetname = NetnameNegotiateContext.ReadFrom(decodedEntries[2].Payload);
                            TestAssertions.Equal(TestEnvironmentDefaults.DefaultServerName, decodedNetname.ServerName, "Decoded NETNAME server name should round-trip through the server's negotiate-context tolerance.");

                            return Task.CompletedTask;
                        }),
            };
        }
    }
}


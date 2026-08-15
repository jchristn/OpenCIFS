namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class CoreNegotiateContextSuiteBuilder
    {
        internal static TestSuiteDescriptor NegotiateContextSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Negotiate",
                displayName: "Negotiate context models",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "NegotiateContextModelsRoundTrip",
                        displayName: "Negotiate context models round-trip deterministic payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            PreauthIntegrityCapabilities preauth = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
                            };

                            byte[] preauthBytes = preauth.ToByteArray();
                            PreauthIntegrityCapabilities parsedPreauth = PreauthIntegrityCapabilities.ReadFrom(preauthBytes);
                            TestAssertions.Equal(1, parsedPreauth.HashAlgorithms.Length, "Unexpected preauth hash algorithm count.");
                            TestAssertions.Equal(HashAlgorithmId.Sha512, parsedPreauth.HashAlgorithms[0], "Unexpected preauth hash algorithm.");
                            TestAssertions.SequenceEqual(preauth.Salt, parsedPreauth.Salt, "Unexpected preauth salt bytes.");

                            SigningCapabilities signing = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.HmacSha256, SigningAlgorithmId.AesGmac }
                            };

                            byte[] signingBytes = signing.ToByteArray();
                            SigningCapabilities parsedSigning = SigningCapabilities.ReadFrom(signingBytes);
                            TestAssertions.Equal(2, parsedSigning.SigningAlgorithms.Length, "Unexpected signing algorithm count.");
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, parsedSigning.SigningAlgorithms[0], "Unexpected first signing algorithm.");
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, parsedSigning.SigningAlgorithms[1], "Unexpected second signing algorithm.");

                            Smb2NegotiateContextHeader header = new Smb2NegotiateContextHeader
                            {
                                ContextType = Smb2NegotiateContextType.SigningCapabilities,
                                DataLength = (ushort)signingBytes.Length,
                                Reserved = 7
                            };

                            Smb2NegotiateContextHeader parsedHeader = Smb2NegotiateContextHeader.ReadFrom(header.ToByteArray());
                            TestAssertions.Equal(Smb2NegotiateContextType.SigningCapabilities, parsedHeader.ContextType, "Unexpected negotiate context type.");
                            TestAssertions.Equal((ushort)signingBytes.Length, parsedHeader.DataLength, "Unexpected negotiate context payload length.");
                            TestAssertions.Equal(7U, parsedHeader.Reserved, "Unexpected negotiate context reserved field.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "EncryptionAndNetnameNegotiateContextsRoundTripDeterministicPayloads",
                        displayName: "Encryption and NETNAME negotiate context models round-trip deterministic payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            EncryptionCapabilities encryption = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            };
                            byte[] encryptionBytes = encryption.ToByteArray();
                            EncryptionCapabilities parsedEncryption = EncryptionCapabilities.ReadFrom(encryptionBytes);
                            TestAssertions.Equal(3, parsedEncryption.Ciphers.Length, "Unexpected encryption cipher count.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, parsedEncryption.Ciphers[0], "Unexpected first cipher.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, parsedEncryption.Ciphers[1], "Unexpected second cipher.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Ccm, parsedEncryption.Ciphers[2], "Unexpected third cipher.");

                            NetnameNegotiateContext netname = new NetnameNegotiateContext
                            {
                                ServerName = "files.example.test"
                            };
                            byte[] netnameBytes = netname.ToByteArray();
                            NetnameNegotiateContext parsedNetname = NetnameNegotiateContext.ReadFrom(netnameBytes);
                            TestAssertions.Equal("files.example.test", parsedNetname.ServerName, "Unexpected NETNAME server name.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "NegotiateContextReadersRejectMalformedInputs",
                        displayName: "Negotiate context readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextHeader.ReadFrom(new byte[7]),
                                "A truncated negotiate context header should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => PreauthIntegrityCapabilities.ReadFrom(new byte[] { 0x00, 0x00, 0x00, 0x00 }),
                                "Preauth integrity capabilities without algorithms should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SigningCapabilities.ReadFrom(new byte[] { 0x00, 0x00, 0x00, 0x00 }),
                                "Signing capabilities without algorithms should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => EncryptionCapabilities.ReadFrom(new byte[] { 0x00, 0x00 }),
                                "Encryption capabilities without ciphers should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => EncryptionCapabilities.ReadFrom(new byte[] { 0x02, 0x00, 0x01, 0x00 }),
                                "Encryption capabilities truncated for the declared cipher count should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetnameNegotiateContext.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "NETNAME negotiate context with an odd-length payload should fail to parse.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListEncodesAndDecodesAlignedTypedEntries",
                        displayName: "SMB 3.1.1 negotiate context list encodes and decodes 8-byte aligned typed entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x11, 0x22, 0x33 }
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
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac, SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            }.ToByteArray();

                            Smb2NegotiateContextEntry[] entries = new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            };

                            byte[] encoded = Smb2NegotiateContextList.Encode(entries);

                            int firstEntrySize = ((8 + preauthPayload.Length + 7) / 8) * 8;
                            int secondEntrySize = ((8 + encryptionPayload.Length + 7) / 8) * 8;
                            int thirdEntrySize = 8 + signingPayload.Length;
                            int expectedLength = firstEntrySize + secondEntrySize + thirdEntrySize;
                            TestAssertions.Equal(expectedLength, encoded.Length, "Encoded SMB 3.1.1 negotiate context list length should reflect 8-byte padding between entries and no required padding after the final entry.");

                            Smb2NegotiateContextEntry[] decoded = Smb2NegotiateContextList.Decode(encoded, entries.Length);
                            TestAssertions.Equal(3, decoded.Length, "Unexpected decoded negotiate context count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decoded[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decoded[1].ContextType, "Unexpected second decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.SigningCapabilities, decoded[2].ContextType, "Unexpected third decoded context type.");
                            TestAssertions.SequenceEqual(preauthPayload, decoded[0].Payload, "Unexpected preauth payload bytes.");
                            TestAssertions.SequenceEqual(encryptionPayload, decoded[1].Payload, "Unexpected encryption payload bytes.");
                            TestAssertions.SequenceEqual(signingPayload, decoded[2].Payload, "Unexpected signing payload bytes.");

                            PreauthIntegrityCapabilities parsedPreauth = PreauthIntegrityCapabilities.ReadFrom(decoded[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, parsedPreauth.HashAlgorithms[0], "Decoded preauth payload should round-trip through PreauthIntegrityCapabilities.ReadFrom.");
                            EncryptionCapabilities parsedEncryption = EncryptionCapabilities.ReadFrom(decoded[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, parsedEncryption.Ciphers[0], "Decoded encryption payload should round-trip through EncryptionCapabilities.ReadFrom.");
                            SigningCapabilities parsedSigning = SigningCapabilities.ReadFrom(decoded[2].Payload);
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, parsedSigning.SigningAlgorithms[0], "Decoded signing payload should round-trip through SigningCapabilities.ReadFrom.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateRequestRoundTripsTypedNegotiateContextEntries",
                        displayName: "SMB 3.1.1 negotiate request round-trips typed negotiate-context entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x42 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes128Gcm }
                            }.ToByteArray();

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                ClientGuid = Guid.Parse("9F2A4D58-1F00-4D44-8E76-7F7B5F4F8B72"),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            request.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload }
                            });

                            byte[] requestBytes = request.ToByteArray();
                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)2, parsedRequest.NegotiateContextCount, "Unexpected SMB 3.1.1 negotiate context count after round-trip.");
                            Smb2NegotiateContextEntry[] decodedEntries = parsedRequest.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(2, decodedEntries.Length, "Unexpected decoded negotiate-context entry count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decodedEntries[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decodedEntries[1].ContextType, "Unexpected second decoded context type.");
                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateResponseRoundTripsTypedNegotiateContextEntries",
                        displayName: "SMB 3.1.1 negotiate response round-trips typed negotiate-context entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x55, 0x66, 0x77, 0x88 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm }
                            }.ToByteArray();

                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                Dialect = SmbDialect.Smb311,
                                ServerGuid = Guid.Parse("0F11D8A6-3344-4F2C-8FB0-1A6E6F7B9C50"),
                                Capabilities = Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 1048576,
                                MaxReadSize = 1048576,
                                MaxWriteSize = 1048576,
                                SystemTime = 0x01D8112233445566UL,
                                ServerStartTime = 0x01D811223344AABBUL,
                                SecurityBuffer = new byte[] { 0xA0, 0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 }
                            };
                            response.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload }
                            });

                            byte[] responseBytes = response.ToByteArray();
                            Smb2NegotiateResponse parsedResponse = Smb2NegotiateResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(SmbDialect.Smb311, parsedResponse.Dialect, "Unexpected SMB 3.1.1 negotiate response dialect after round-trip.");
                            TestAssertions.Equal((ushort)2, parsedResponse.NegotiateContextCount, "Unexpected SMB 3.1.1 negotiate context count after round-trip.");
                            TestAssertions.SequenceEqual(response.SecurityBuffer, parsedResponse.SecurityBuffer, "SecurityBuffer should round-trip on the SMB 3.1.1 negotiate response.");

                            Smb2NegotiateContextEntry[] decodedEntries = parsedResponse.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(2, decodedEntries.Length, "Unexpected decoded negotiate-context entry count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decodedEntries[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decodedEntries[1].ContextType, "Unexpected second decoded context type.");
                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip on the response.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip on the response.");

                            Smb2NegotiateResponse smb302Response = new Smb2NegotiateResponse
                            {
                                Dialect = SmbDialect.Smb302,
                                SecurityBuffer = new byte[] { 0x01, 0x02, 0x03 }
                            };
                            byte[] smb302ResponseBytes = smb302Response.ToByteArray();
                            Smb2NegotiateResponse parsedSmb302Response = Smb2NegotiateResponse.ReadFrom(smb302ResponseBytes);
                            TestAssertions.Equal((ushort)0, parsedSmb302Response.NegotiateContextCount, "SMB 3.0.2 negotiate responses should not carry SMB 3.1.1 negotiate-context counts.");
                            TestAssertions.Equal(0, parsedSmb302Response.NegotiateContextData.Length, "SMB 3.0.2 negotiate responses should not carry SMB 3.1.1 negotiate-context bytes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListRejectsTruncatedAndOversizedInputs",
                        displayName: "SMB 3.1.1 negotiate context list rejects truncated headers and payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(new byte[] { 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 }, 1),
                                "Truncated context-header buffers should fail to decode.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(new byte[] { 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA }, 1),
                                "Context payloads truncated below the declared length should fail to decode.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextSelectorPicksSupportedAlgorithmsAndRejectsUnsupportedClientOffers",
                        displayName: "SMB 3.1.1 negotiate-context selector picks supported algorithms and rejects unsupported client offers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            HashAlgorithmId selectedHash = Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(
                                new PreauthIntegrityCapabilities
                                {
                                    HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                    Salt = new byte[] { 0xAA }
                                });
                            TestAssertions.Equal(HashAlgorithmId.Sha512, selectedHash, "Selector should pick SHA-512 when offered.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(new PreauthIntegrityCapabilities
                                {
                                    HashAlgorithms = new HashAlgorithmId[] { (HashAlgorithmId)0x9999 },
                                    Salt = Array.Empty<byte>()
                                }),
                                "Selector should reject SMB 3.1.1 client preauth offers without a supported hash algorithm.");
                            TestAssertions.Throws<ArgumentNullException>(
                                () => Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(null!),
                                "Selector should reject null preauth-capability inputs.");

                            SigningAlgorithmId defaultSigning = Smb311NegotiateContextSelector.SelectSigningAlgorithm(null);
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, defaultSigning, "Selector should default to HMAC-SHA256 when no signing context is present.");

                            SigningAlgorithmId gmacFromMixed = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac, SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, gmacFromMixed, "Selector should prefer AES-GMAC over AES-CMAC and HMAC-SHA256 when offered.");

                            SigningAlgorithmId aesCmacFromCmacAndHmac = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesCmac, aesCmacFromCmacAndHmac, "Selector should fall back to AES-CMAC when AES-GMAC is not offered.");

                            SigningAlgorithmId gmacOnlyAccepted = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, gmacOnlyAccepted, "Selector should accept SMB 3.1.1 signing offers that contain only AES-GMAC now that per-message GMAC signing is wired.");

                            SigningAlgorithmId hmacFromHmacOnly = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, hmacFromHmacOnly, "Selector should fall back to HMAC-SHA256 when neither AES-GMAC nor AES-CMAC is offered.");

                            SmbCipherAlgorithmId? noCipherSelected = Smb311NegotiateContextSelector.SelectCipher(null);
                            TestAssertions.True(noCipherSelected == null, "Selector should return null when no encryption context is offered.");

                            SmbCipherAlgorithmId? gcmPreferredSelected = Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm, SmbCipherAlgorithmId.Aes128Gcm, SmbCipherAlgorithmId.Aes128Ccm }
                            });
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, gcmPreferredSelected!.Value, "Selector should prefer AES-128-GCM over AES-128-CCM when both are offered.");

                            SmbCipherAlgorithmId? aes128CcmFallback = Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm, SmbCipherAlgorithmId.Aes128Ccm }
                            });
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Ccm, aes128CcmFallback!.Value, "Selector should fall back to AES-128-CCM when AES-128-GCM is not offered.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                                {
                                    Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm }
                                }),
                                "Selector should reject encryption offers without AES-128-GCM or AES-128-CCM until AES-256 ciphers are wired.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListRejectsTamperedCountAndPayloads",
                        displayName: "SMB 3.1.1 negotiate context list rejects tampered context counts and tampered payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB }
                            }.ToByteArray();
                            byte[] signingPayload = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac }
                            }.ToByteArray();

                            Smb2NegotiateContextEntry[] entries = new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            };

                            byte[] encoded = Smb2NegotiateContextList.Encode(entries);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(encoded, entries.Length + 1),
                                "Decoding with an inflated entry count beyond the carried payload should be rejected.");

                            byte[] tamperedHashCount = (byte[])encoded.Clone();
                            tamperedHashCount[8] = 0x00;
                            tamperedHashCount[9] = 0x00;
                            Smb2NegotiateContextEntry[] decodedAfterTamper = Smb2NegotiateContextList.Decode(tamperedHashCount, entries.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => PreauthIntegrityCapabilities.ReadFrom(decodedAfterTamper[0].Payload),
                                "A preauth context with a zeroed hash-algorithm count should be rejected by the typed reader after decode.");

                            byte[] tamperedHashAlgorithm = (byte[])encoded.Clone();
                            tamperedHashAlgorithm[12] = 0xFF;
                            tamperedHashAlgorithm[13] = 0xFF;
                            Smb2NegotiateContextEntry[] decodedTamperedAlgorithm = Smb2NegotiateContextList.Decode(tamperedHashAlgorithm, entries.Length);
                            PreauthIntegrityCapabilities tamperedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedTamperedAlgorithm[0].Payload);
                            TestAssertions.True(
                                tamperedPreauth.HashAlgorithms[0] != HashAlgorithmId.Sha512,
                                "A bytewise-tampered preauth payload should not match the original hash-algorithm identifier.");

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                Dialects = new SmbDialect[] { SmbDialect.Smb311 }
                            };
                            request.SetNegotiateContextEntries(entries);
                            byte[] requestBytes = request.ToByteArray();
                            byte[] tamperedRequestBytes = (byte[])requestBytes.Clone();
                            int contextOffsetField = 28;
                            tamperedRequestBytes[contextOffsetField] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 1] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 2] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(tamperedRequestBytes),
                                "Tampering an SMB 3.1.1 negotiate request to point its negotiate-context offset below the fixed header should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}


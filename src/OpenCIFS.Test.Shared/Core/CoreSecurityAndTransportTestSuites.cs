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
    internal static class CoreSecurityAndTransportTestSuites
    {
        internal static TestSuiteDescriptor SecurityFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Security",
                displayName: "Security foundation primitives",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "PreauthHashAccumulatorMatchesTranscriptHash",
                        displayName: "Preauth hash accumulator matches the expected transcript hash",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] message1 = new byte[] { 0x01, 0x02, 0x03 };
                            byte[] message2 = new byte[] { 0x10, 0x20, 0x30, 0x40 };
                            PreauthIntegrityHashAccumulator accumulator = new PreauthIntegrityHashAccumulator();

                            accumulator.Append(message1);
                            byte[] expectedAfterMessage1 = SHA512.HashData(Combine(new byte[64], message1));
                            TestAssertions.SequenceEqual(expectedAfterMessage1, accumulator.CurrentHash, "Unexpected preauth transcript hash after the first message.");

                            accumulator.Append(message2);
                            byte[] expectedAfterMessage2 = SHA512.HashData(Combine(expectedAfterMessage1, message2));
                            TestAssertions.SequenceEqual(expectedAfterMessage2, accumulator.CurrentHash, "Unexpected preauth transcript hash after the second message.");

                            accumulator.Reset();
                            TestAssertions.SequenceEqual(new byte[64], accumulator.CurrentHash, "Reset should restore the zero transcript hash.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "PreauthHashAccumulatorRejectsUnsupportedAlgorithms",
                        displayName: "Preauth hash accumulator rejects unsupported algorithms",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<NotSupportedException>(
                                () => new PreauthIntegrityHashAccumulator((HashAlgorithmId)0xFFFF),
                                "Unsupported preauth algorithms should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SigningAndKeyDerivationContractsRemainInterfaces",
                        displayName: "Signing and key-derivation contracts remain stable and discoverable",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Type messageSignerType = typeof(IMessageSigner);
                            Type keyDerivationProviderType = typeof(IKeyDerivationProvider);

                            TestAssertions.True(messageSignerType.IsInterface, "IMessageSigner must remain an interface.");
                            TestAssertions.True(keyDerivationProviderType.IsInterface, "IKeyDerivationProvider must remain an interface.");
                            TestAssertions.True(messageSignerType.GetProperty("AlgorithmId") != null, "IMessageSigner must expose AlgorithmId.");
                            TestAssertions.True(messageSignerType.GetProperty("SignatureLength") != null, "IMessageSigner must expose SignatureLength.");
                            TestAssertions.True(messageSignerType.GetProperty("RequiresNonce") != null, "IMessageSigner must expose RequiresNonce.");
                            TestAssertions.True(messageSignerType.GetMethod("Sign") != null, "IMessageSigner must expose Sign.");
                            TestAssertions.True(messageSignerType.GetMethod("Verify") != null, "IMessageSigner must expose Verify.");
                            TestAssertions.True(keyDerivationProviderType.GetMethod("DeriveKey") != null, "IKeyDerivationProvider must expose DeriveKey.");
                            TestAssertions.True(typeof(MessageSignerFactory).GetMethod("Create") != null, "MessageSignerFactory must expose Create.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Smb3TransformPacketsRoundTripWithAes128Ccm",
                        displayName: "SMB3 transform packets round-trip with AES-128-CCM and preserve the declared session identifier",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] key = Hex("00112233445566778899AABBCCDDEEFF");
                            byte[] plaintextPacket = Hex("FE534D424000000000000000030000000100000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000400000000000000");
                            byte[] encryptedPacket = Smb3MessageTransform.EncryptPacket(plaintextPacket, 0x0102030405060708UL, key);
                            Smb2TransformHeader header = Smb2TransformHeader.ReadFrom(encryptedPacket);

                            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedPacket), "Expected the encrypted SMB3 packet to begin with a transform header.");
                            TestAssertions.Equal(0x0102030405060708UL, header.SessionId, "Expected the SMB3 transform header to preserve the supplied session identifier.");
                            TestAssertions.Equal((uint)plaintextPacket.Length, header.OriginalMessageSize, "Expected the SMB3 transform header to preserve the plaintext packet length.");
                            TestAssertions.Equal((ushort)0x0001, header.Flags, "Expected the bounded SMB3 transform header to preserve the fixed transform-flag value.");
                            TestAssertions.SequenceEqual(
                                plaintextPacket,
                                Smb3MessageTransform.DecryptPacket(encryptedPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected the SMB3 transform packet to decrypt back to the original plaintext bytes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Smb3TransformPacketsRejectTamperingAndMalformedLengths",
                        displayName: "SMB3 transform packets reject tampering and malformed declared lengths",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] key = Hex("00112233445566778899AABBCCDDEEFF");
                            byte[] plaintextPacket = Hex("FE534D424000000000000000030000000100000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000400000000000000");
                            byte[] encryptedPacket = Smb3MessageTransform.EncryptPacket(plaintextPacket, 0x0102030405060708UL, key);

                            byte[] tamperedPacket = (byte[])encryptedPacket.Clone();
                            tamperedPacket[tamperedPacket.Length - 1] ^= 0x01;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb3MessageTransform.DecryptPacket(tamperedPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected SMB3 transform packet tampering to fail authentication-tag validation.");

                            byte[] malformedLengthPacket = (byte[])encryptedPacket.Clone();
                            LittleEndianWriter writer = new LittleEndianWriter();
                            writer.WriteUInt32(checked((uint)plaintextPacket.Length + 1));
                            byte[] invalidLengthBytes = writer.ToArray();
                            Buffer.BlockCopy(invalidLengthBytes, 0, malformedLengthPacket, 36, 4);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb3MessageTransform.DecryptPacket(malformedLengthPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected malformed SMB3 transform packet lengths to be rejected before decryption.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Md4AndHmacMd5MatchKnownVectors",
                        displayName: "MD4 and HMAC-MD5 match known-answer vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.md4.empty"),
                                Md4.HashData(Array.Empty<byte>()),
                                "The MD4 digest for the empty string changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.md4.abc"),
                                Md4.HashData(Encoding.ASCII.GetBytes("abc")),
                                "The MD4 digest for 'abc' changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.hmac-md5.hi-there"),
                                HmacMd5.HashData(CreateRepeatedByteArray(0x0B, 16), Encoding.ASCII.GetBytes("Hi There")),
                                "The HMAC-MD5 known-answer vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "NtlmV2ResponsesAndMicMatchMicrosoftVectors",
                        displayName: "NTLMv2 challenge responses and MIC generation match Microsoft vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] expectedResponseKey = GoldenVectorStore.GetBytes("core.security.ntlm.response-key");
                            NtlmV2ClientChallenge clientChallenge = CreateMicrosoftNtlmV2ClientChallenge();
                            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                clientChallenge: clientChallenge);

                            TestAssertions.SequenceEqual(expectedResponseKey, responseSet.ResponseKeyNt, "The NTLMv2 response key changed.");
                            TestAssertions.SequenceEqual(expectedResponseKey, responseSet.ResponseKeyLm, "The LMv2 response key changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.nt-challenge-response"),
                                responseSet.NtChallengeResponse.ToByteArray(),
                                "The NTLMv2 NT challenge response changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.lm-challenge-response"),
                                responseSet.LmChallengeResponse,
                                "The LMv2 challenge response changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.session-base-key"),
                                responseSet.SessionBaseKey,
                                "The NTLMv2 session-base key changed.");

                            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: responseSet.LmChallengeResponse,
                                verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet);
                            TestAssertions.True(verified, "The Microsoft NTLMv2 example should verify successfully.");
                            TestAssertions.True(verifiedResponseSet != null, "Verification should return a response set.");
                            TestAssertions.SequenceEqual(responseSet.SessionBaseKey, verifiedResponseSet!.SessionBaseKey, "Verification changed the session-base key.");

                            bool verifiedWithOmittedLm = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: Array.Empty<byte>(),
                                verifiedResponseSet: out _);
                            TestAssertions.True(verifiedWithOmittedLm, "NTLMv2 verification should accept an omitted LM response when the NT response is valid.");

                            bool verifiedWithZeroLm = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: new byte[24],
                                verifiedResponseSet: out _);
                            TestAssertions.True(verifiedWithZeroLm, "NTLMv2 verification should accept a zeroed LM response when the NT response is valid.");

                            byte[] expectedMic = GoldenVectorStore.GetBytes("core.security.ntlm.mic");
                            byte[] mic = NtlmMessageIntegrityCode.Compute(
                                exportedSessionKey: CreateRepeatedByteArray(0x55, 16),
                                negotiateMessage: new byte[] { 0x01, 0x02, 0x03 },
                                challengeMessage: new byte[] { 0x04, 0x05 },
                                authenticateMessageWithZeroMic: new byte[] { 0x06, 0x07, 0x08 });
                            TestAssertions.SequenceEqual(expectedMic, mic, "The NTLM MIC known-answer vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SpnegoTokensRoundTripAndNegotiateMechanisms",
                        displayName: "SPNEGO tokens round-trip and negotiate a mutual mechanism",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SpnegoNegTokenInit initToken = new SpnegoNegTokenInit
                            {
                                MechanismTypes = new string[] { SpnegoMechanismOid.Kerberos, SpnegoMechanismOid.Ntlm },
                                RequestFlags = 0xA0000000U,
                                MechanismToken = Hex("01020304"),
                                MechanismListMic = Hex("AABBCCDD")
                            };

                            byte[] encodedInitToken = SpnegoTokenCodec.EncodeNegTokenInit(initToken);
                            TestAssertions.Equal((byte)0x60, encodedInitToken[0], "SPNEGO initial tokens should carry the GSS-API application wrapper.");

                            SpnegoNegTokenInit decodedInitToken = SpnegoTokenCodec.DecodeNegTokenInit(encodedInitToken);
                            TestAssertions.Equal(2, decodedInitToken.MechanismTypes.Length, "Unexpected SPNEGO mechanism count.");
                            TestAssertions.Equal(SpnegoMechanismOid.Kerberos, decodedInitToken.MechanismTypes[0], "Unexpected first SPNEGO mechanism OID.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, decodedInitToken.MechanismTypes[1], "Unexpected second SPNEGO mechanism OID.");
                            TestAssertions.Equal(0xA0000000U, decodedInitToken.RequestFlags!.Value, "Unexpected SPNEGO request flags.");
                            TestAssertions.SequenceEqual(Hex("01020304"), decodedInitToken.MechanismToken!, "Unexpected SPNEGO optimistic token bytes.");
                            TestAssertions.SequenceEqual(Hex("AABBCCDD"), decodedInitToken.MechanismListMic!, "Unexpected SPNEGO MIC bytes.");

                            bool selected = SpnegoMechanismNegotiator.TrySelectMechanism(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                                selectedMechanism: out string? selectedMechanism);
                            TestAssertions.True(selected, "The NTLM mechanism should be selected from the offered list.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, selectedMechanism, "The selected SPNEGO mechanism changed.");

                            SpnegoNegTokenResp responseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                                mechanismResponseToken: Hex("05060708"),
                                completed: false);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, responseToken.NegotiationState!.Value, "Unexpected SPNEGO negotiation state.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, responseToken.SupportedMechanism, "Unexpected SPNEGO selected mechanism.");
                            TestAssertions.SequenceEqual(Hex("05060708"), responseToken.ResponseToken!, "Unexpected SPNEGO response token bytes.");

                            byte[] encodedResponseToken = SpnegoTokenCodec.EncodeNegTokenResp(responseToken);
                            TestAssertions.Equal((byte)0xA1, encodedResponseToken[0], "SPNEGO response tokens should use the context-specific response wrapper.");

                            SpnegoNegTokenResp decodedResponseToken = SpnegoTokenCodec.DecodeNegTokenResp(encodedResponseToken);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, decodedResponseToken.NegotiationState!.Value, "The SPNEGO response state changed during round-trip.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, decodedResponseToken.SupportedMechanism, "The SPNEGO selected mechanism changed during round-trip.");
                            TestAssertions.SequenceEqual(Hex("05060708"), decodedResponseToken.ResponseToken!, "The SPNEGO response token changed during round-trip.");

                            SpnegoNegTokenResp rejectedResponseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.MicrosoftKerberos });
                            TestAssertions.Equal(SpnegoNegState.Reject, rejectedResponseToken.NegotiationState!.Value, "Unsupported SPNEGO offers should be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "MessageSignersMatchKnownVectorsAndFactorySelection",
                        displayName: "Message signers match known vectors and the factory selects the negotiated algorithm",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            IMessageSigner hmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] hmacSignature = hmacSigner.Sign(
                                message: Encoding.ASCII.GetBytes("Hi There"),
                                signingKey: CreateRepeatedByteArray(0x0B, 20),
                                nonce: ReadOnlySpan<byte>.Empty);
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, hmacSigner.AlgorithmId, "Unexpected HMAC-SHA256 signer algorithm identifier.");
                            TestAssertions.False(hmacSigner.RequiresNonce, "The HMAC-SHA256 signer should not require a nonce.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.signing.hmac-sha256"),
                                hmacSignature,
                                "The SMB HMAC-SHA256 signature vector changed.");
                            TestAssertions.True(
                                hmacSigner.Verify(Encoding.ASCII.GetBytes("Hi There"), CreateRepeatedByteArray(0x0B, 20), ReadOnlySpan<byte>.Empty, hmacSignature),
                                "The HMAC-SHA256 signer should verify its own signature.");

                            byte[] aesCmacKey = Hex("2B7E151628AED2A6ABF7158809CF4F3C");
                            byte[] aesCmacMessage = Hex("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
                            byte[] aesCmacSignature = AesCmac.ComputeMac(aesCmacKey, aesCmacMessage);
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.signing.aes-cmac"),
                                aesCmacSignature,
                                "The AES-CMAC known-answer vector changed.");

                            IMessageSigner aesCmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.Equal(SigningAlgorithmId.AesCmac, aesCmacSigner.AlgorithmId, "Unexpected AES-CMAC signer algorithm identifier.");
                            TestAssertions.False(aesCmacSigner.RequiresNonce, "The AES-CMAC signer should not require a nonce.");
                            TestAssertions.SequenceEqual(aesCmacSignature, aesCmacSigner.Sign(aesCmacMessage, aesCmacKey, ReadOnlySpan<byte>.Empty), "The AES-CMAC signer changed the CMAC output.");

                            IMessageSigner aesGmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, aesGmacSigner.AlgorithmId, "Unexpected AES-GMAC signer algorithm identifier.");
                            TestAssertions.True(aesGmacSigner.RequiresNonce, "The AES-GMAC signer should require a nonce.");
                            TestAssertions.Equal(16, aesGmacSigner.SignatureLength, "The AES-GMAC signer should produce 16-byte signatures.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "HkdfAndCounterModeKdfMatchKnownVectors",
                        displayName: "HKDF and counter-mode SMB key derivation match known vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] hkdfInputKeyMaterial = Hex("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
                            byte[] hkdfSalt = Hex("000102030405060708090A0B0C");
                            byte[] hkdfInfo = Hex("F0F1F2F3F4F5F6F7F8F9");
                            byte[] expectedPrk = GoldenVectorStore.GetBytes("core.security.hkdf.prk");
                            byte[] expectedOkm = GoldenVectorStore.GetBytes("core.security.hkdf.okm");

                            byte[] actualPrk = HkdfSha256.Extract(hkdfInputKeyMaterial, hkdfSalt);
                            byte[] actualOkmFromExpand = HkdfSha256.Expand(expectedPrk, hkdfInfo, 42);
                            byte[] actualOkmFromDerive = HkdfSha256.DeriveKey(hkdfInputKeyMaterial, hkdfSalt, hkdfInfo, 42);

                            TestAssertions.SequenceEqual(expectedPrk, actualPrk, "The HKDF-Extract vector changed.");
                            TestAssertions.SequenceEqual(expectedOkm, actualOkmFromExpand, "The HKDF-Expand vector changed.");
                            TestAssertions.SequenceEqual(expectedOkm, actualOkmFromDerive, "The HKDF combined derive vector changed.");

                            CounterModeKeyDerivationProvider provider = new CounterModeKeyDerivationProvider();
                            byte[] smb30SigningKey = provider.DeriveKey(
                                sessionSecret: CreateRepeatedByteArray(0x55, 16),
                                label: Encoding.ASCII.GetBytes("SMB2AESCMAC\0"),
                                context: Encoding.ASCII.GetBytes("SmbSign\0"),
                                outputLength: 16);
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.hkdf.smb30-signing-key"),
                                smb30SigningKey,
                                "The SMB counter-mode signing-key vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SmbSessionKeyDerivationMatchesDialectAndCipherRules",
                        displayName: "SMB session subkeys match dialect labels, contexts, and cipher-length rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SmbSessionKeySet smb30KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    Dialect = SmbDialect.Smb30,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Ccm
                                });
                            TestAssertions.SequenceEqual(Hex("A2F3731F7E58FDAF7E6DE4871BB7D7D3"), smb30KeySet.SigningKey, "The SMB 3.0 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("E88F948B20805C86BEB4584CB58DC16A"), smb30KeySet.ApplicationKey, "The SMB 3.0 application key changed.");
                            TestAssertions.SequenceEqual(Hex("A91ADF01E344C4319BF664CFA7C70905"), smb30KeySet.EncryptionKey, "The SMB 3.0 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("FC74A0A2CA6E60B65E2B93CD6863B138"), smb30KeySet.DecryptionKey, "The SMB 3.0 decryption key changed.");

                            SmbSessionKeySet smb311Aes128KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    Dialect = SmbDialect.Smb311,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Gcm,
                                    PreauthIntegrityHash = CreateSequentialByteArray(64)
                                });
                            TestAssertions.SequenceEqual(Hex("2826DB04880B2879DDC7CE91EC5277A7"), smb311Aes128KeySet.SigningKey, "The SMB 3.1.1 AES-128 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("91C53D0EED81519D539D2800434A2293"), smb311Aes128KeySet.ApplicationKey, "The SMB 3.1.1 AES-128 application key changed.");
                            TestAssertions.SequenceEqual(Hex("89479974D6E3217E9185FD27E39C8DA2"), smb311Aes128KeySet.EncryptionKey, "The SMB 3.1.1 AES-128 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("1974E6587A668A8F215393970CECF616"), smb311Aes128KeySet.DecryptionKey, "The SMB 3.1.1 AES-128 decryption key changed.");

                            SmbSessionKeySet smb311Aes256KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    FullSessionKey = CreateSequentialByteArray(32),
                                    Dialect = SmbDialect.Smb311,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes256Gcm,
                                    PreauthIntegrityHash = CreateSequentialByteArray(64)
                                });
                            TestAssertions.SequenceEqual(Hex("5C2A51D834DFBCFA4B53286B3C7CAAC1AE47F2DFDC05A08C2379987CDC08788A"), smb311Aes256KeySet.SigningKey, "The SMB 3.1.1 AES-256 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("D4E23809E89E44ADEC7AEE207C054699D67EED2A261D2DEEE63BF0C229D5FB49"), smb311Aes256KeySet.ApplicationKey, "The SMB 3.1.1 AES-256 application key changed.");
                            TestAssertions.SequenceEqual(Hex("53F8B2FB513A90F5231F5AC12BA0A24B9EED8F6E80596136560F1B0003E8D2AE"), smb311Aes256KeySet.EncryptionKey, "The SMB 3.1.1 AES-256 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("E568DE865AE188F20138931C5423898FC0D5E94FA094B72D474FC56CF5703DB6"), smb311Aes256KeySet.DecryptionKey, "The SMB 3.1.1 AES-256 decryption key changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "AeadWrappersAndGmacMatchVectorsAndDetectTampering",
                        displayName: "GMAC and AEAD wrappers match vectors and detect payload tampering",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] gcmKey = Hex("FEFFE9928665731C6D6A8F9467308308");
                            byte[] gcmNonce = Hex("CAFEBABEFACEDBADDECAF888");
                            byte[] gcmPlaintext = Hex("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
                            byte[] gcmAssociatedData = Hex("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
                            byte[] expectedGmac = GoldenVectorStore.GetBytes("core.security.aead.gmac");
                            byte[] expectedGcmCiphertext = GoldenVectorStore.GetBytes("core.security.aead.gcm-ciphertext");
                            byte[] expectedGcmTag = GoldenVectorStore.GetBytes("core.security.aead.gcm-tag");

                            byte[] gmac = AesGmac.ComputeMac(gcmKey, gcmNonce, gcmAssociatedData);
                            TestAssertions.SequenceEqual(expectedGmac, gmac, "The AES-GMAC vector changed.");

                            IMessageSigner gmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            TestAssertions.SequenceEqual(expectedGmac, gmacSigner.Sign(gcmAssociatedData, gcmKey, gcmNonce), "The AES-GMAC signer changed the NIST vector.");
                            TestAssertions.True(gmacSigner.Verify(gcmAssociatedData, gcmKey, gcmNonce, expectedGmac), "The AES-GMAC signer should verify the known-answer vector.");

                            AeadCipherResult gcmCipherResult = AesGcmCipher.Encrypt(gcmKey, gcmNonce, gcmPlaintext, Array.Empty<byte>());
                            TestAssertions.SequenceEqual(expectedGcmCiphertext, gcmCipherResult.Ciphertext, "The AES-GCM ciphertext vector changed.");
                            TestAssertions.SequenceEqual(expectedGcmTag, gcmCipherResult.AuthenticationTag, "The AES-GCM tag vector changed.");
                            TestAssertions.SequenceEqual(gcmPlaintext, AesGcmCipher.Decrypt(gcmKey, gcmNonce, gcmCipherResult.Ciphertext, gcmCipherResult.AuthenticationTag, Array.Empty<byte>()), "The AES-GCM decrypt path changed the plaintext.");

                            byte[] ccmKey = Hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
                            byte[] ccmNonce = Hex("00000003020100A0A1A2A3A4A5");
                            byte[] ccmAssociatedData = Hex("0001020304050607");
                            byte[] ccmPlaintext = Hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
                            AeadCipherResult ccmCipherResult = AesCcmCipher.Encrypt(ccmKey, ccmNonce, ccmPlaintext, ccmAssociatedData, tagLength: 8);
                            TestAssertions.SequenceEqual(GoldenVectorStore.GetBytes("core.security.aead.ccm-ciphertext"), ccmCipherResult.Ciphertext, "The AES-CCM ciphertext vector changed.");
                            TestAssertions.SequenceEqual(GoldenVectorStore.GetBytes("core.security.aead.ccm-tag"), ccmCipherResult.AuthenticationTag, "The AES-CCM tag vector changed.");
                            TestAssertions.SequenceEqual(ccmPlaintext, AesCcmCipher.Decrypt(ccmKey, ccmNonce, ccmCipherResult.Ciphertext, ccmCipherResult.AuthenticationTag, ccmAssociatedData), "The AES-CCM decrypt path changed the plaintext.");

                            byte[] corruptedGcmTag = CreateMutatedCopy(gcmCipherResult.AuthenticationTag);
                            TestAssertions.Throws<CryptographicException>(
                                () => AesGcmCipher.Decrypt(gcmKey, gcmNonce, gcmCipherResult.Ciphertext, corruptedGcmTag, Array.Empty<byte>()),
                                "Corrupt AES-GCM tags should fail authentication.");
                            byte[] corruptedCcmTag = CreateMutatedCopy(ccmCipherResult.AuthenticationTag);
                            TestAssertions.Throws<CryptographicException>(
                                () => AesCcmCipher.Decrypt(ccmKey, ccmNonce, ccmCipherResult.Ciphertext, corruptedCcmTag, ccmAssociatedData),
                                "Corrupt AES-CCM tags should fail authentication.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SecurityPrimitivesRejectInvalidTokensMicsAndSignatures",
                        displayName: "Security primitives reject invalid tokens, MICs, signatures, and unsupported key material",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                clientChallenge: CreateMicrosoftNtlmV2ClientChallenge());
                            byte[] mutatedLmResponse = CreateMutatedCopy(responseSet.LmChallengeResponse);
                            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: mutatedLmResponse,
                                verifiedResponseSet: out NtlmV2ChallengeResponseSet? _);
                            TestAssertions.False(verified, "Corrupt LMv2 responses should not verify.");

                            byte[] validMic = NtlmMessageIntegrityCode.Compute(
                                exportedSessionKey: CreateRepeatedByteArray(0x55, 16),
                                negotiateMessage: new byte[] { 0x01, 0x02, 0x03 },
                                challengeMessage: new byte[] { 0x04, 0x05 },
                                authenticateMessageWithZeroMic: new byte[] { 0x06, 0x07, 0x08 });
                            byte[] mutatedMic = CreateMutatedCopy(validMic);
                            TestAssertions.False(
                                NtlmMessageIntegrityCode.Verify(CreateRepeatedByteArray(0x55, 16), new byte[] { 0x01, 0x02, 0x03 }, new byte[] { 0x04, 0x05 }, new byte[] { 0x06, 0x07, 0x08 }, mutatedMic),
                                "Corrupt NTLM MIC values should not verify.");

                            IMessageSigner hmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] hmacSignature = hmacSigner.Sign(Encoding.ASCII.GetBytes("sign me"), Hex("00112233445566778899AABBCCDDEEFF"), ReadOnlySpan<byte>.Empty);
                            TestAssertions.False(
                                hmacSigner.Verify(Encoding.ASCII.GetBytes("sign me"), Hex("00112233445566778899AABBCCDDEEFF"), ReadOnlySpan<byte>.Empty, CreateMutatedCopy(hmacSignature)),
                                "Corrupt HMAC-SHA256 signatures should not verify.");

                            IMessageSigner cmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            byte[] cmacSignature = cmacSigner.Sign(Hex("11223344556677889900AABBCCDDEEFF"), Hex("2B7E151628AED2A6ABF7158809CF4F3C"), ReadOnlySpan<byte>.Empty);
                            TestAssertions.False(
                                cmacSigner.Verify(Hex("11223344556677889900AABBCCDDEEFF"), Hex("2B7E151628AED2A6ABF7158809CF4F3C"), ReadOnlySpan<byte>.Empty, CreateMutatedCopy(cmacSignature)),
                                "Corrupt AES-CMAC signatures should not verify.");

                            IMessageSigner gmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            byte[] gmacSignature = gmacSigner.Sign(Hex("AABBCCDD"), Hex("FEFFE9928665731C6D6A8F9467308308"), Hex("CAFEBABEFACEDBADDECAF888"));
                            TestAssertions.False(
                                gmacSigner.Verify(Hex("AABBCCDD"), Hex("FEFFE9928665731C6D6A8F9467308308"), Hex("CAFEBABEFACEDBADDECAF888"), CreateMutatedCopy(gmacSignature)),
                                "Corrupt AES-GMAC signatures should not verify.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SpnegoTokenCodec.DecodeNegTokenInit(Hex("600306012A")),
                                "Malformed SPNEGO NegTokenInit payloads should fail decoding.");
                            TestAssertions.Throws<ArgumentException>(
                                () => SmbSessionKeyDerivation.DeriveEncryptionKey(
                                    new SmbKeyDerivationInputs
                                    {
                                        SessionKey = CreateRepeatedByteArray(0x55, 16),
                                        Dialect = SmbDialect.Smb311,
                                        CipherAlgorithmId = SmbCipherAlgorithmId.Aes256Gcm,
                                        PreauthIntegrityHash = CreateSequentialByteArray(64)
                                    }),
                                "SMB 3.1.1 AES-256 encryption derivation should require a full session key.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the transport foundation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor TransportFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Transport",
                displayName: "Transport codec and pipe foundations",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "TransportOptionsClampCapacities",
                        displayName: "Transport connection options clamp capacities",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            FramedPipeConnectionOptions options = new FramedPipeConnectionOptions
                            {
                                InboundFrameCapacity = 0,
                                OutboundFrameCapacity = 10000
                            };

                            TestAssertions.Equal(1, options.InboundFrameCapacity, "Inbound capacity should clamp to the minimum.");
                            TestAssertions.Equal(4096, options.OutboundFrameCapacity, "Outbound capacity should clamp to the maximum.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FrameProtocolsRoundTripAndRejectMalformedInputs",
                        displayName: "Frame protocols round-trip payloads and reject malformed inputs",
                        executeAsync: async token =>
                        {
                            using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                            timeoutSource.CancelAfter(TimeSpan.FromSeconds(5));
                            CancellationToken timeoutToken = timeoutSource.Token;

                            byte[] directPayload = new byte[] { 0x01, 0x02, 0x03 };
                            DirectTcpFrameProtocol directProtocol = new DirectTcpFrameProtocol();
                            Pipe directPipe = new Pipe();
                            await directProtocol.WriteFrameAsync(directPipe.Writer, directPayload, timeoutToken).ConfigureAwait(false);
                            await directPipe.Writer.FlushAsync(timeoutToken).ConfigureAwait(false);
                            await directPipe.Writer.CompleteAsync().ConfigureAwait(false);
                            byte[] decodedDirectPayload = await ReadFrameFromPipeAsync(directPipe.Reader, directProtocol, timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(directPayload, decodedDirectPayload, "Direct TCP frame protocol changed the payload.");
                            await directPipe.Reader.CompleteAsync().ConfigureAwait(false);

                            byte[] partialDirectFrame = new byte[DirectTcpFrameHeader.Size];
                            byte[] encodedDirectFrame = CreateDirectTcpFrame(directPayload);
                            Array.Copy(encodedDirectFrame, partialDirectFrame, partialDirectFrame.Length);
                            bool hasDirectFrame = directProtocol.TryReadFrame(new ReadOnlySequence<byte>(partialDirectFrame), out byte[]? directPartialPayload, out long directPartialConsumed);
                            TestAssertions.False(hasDirectFrame, "A partial Direct TCP frame should not decode.");
                            TestAssertions.True(directPartialPayload == null, "A partial Direct TCP frame should not return a payload.");
                            TestAssertions.Equal(0L, directPartialConsumed, "A partial Direct TCP frame should not consume bytes.");

                            DirectTcpFrameProtocol constrainedDirectProtocol = new DirectTcpFrameProtocol
                            {
                                MaximumFrameLength = 1024
                            };
                            byte[] oversizedDirectFrame = CreateDirectTcpFrame(new byte[1025]);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () =>
                                {
                                    constrainedDirectProtocol.TryReadFrame(new ReadOnlySequence<byte>(oversizedDirectFrame), out byte[]? _, out long _);
                                },
                                "An oversized Direct TCP frame should fail validation.");

                            byte[] netBiosPayload = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
                            NetBiosSessionServiceFrameProtocol netBiosProtocol = new NetBiosSessionServiceFrameProtocol
                            {
                                MessageType = NetBiosSessionMessageType.SessionMessage
                            };

                            Pipe netBiosPipe = new Pipe();
                            await netBiosProtocol.WriteFrameAsync(netBiosPipe.Writer, netBiosPayload, timeoutToken).ConfigureAwait(false);
                            await netBiosPipe.Writer.FlushAsync(timeoutToken).ConfigureAwait(false);
                            await netBiosPipe.Writer.CompleteAsync().ConfigureAwait(false);
                            byte[] decodedNetBiosPayload = await ReadFrameFromPipeAsync(netBiosPipe.Reader, netBiosProtocol, timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(netBiosPayload, decodedNetBiosPayload, "NetBIOS frame protocol changed the payload.");
                            await netBiosPipe.Reader.CompleteAsync().ConfigureAwait(false);

                            byte[] partialNetBiosFrame = new byte[NetBiosSessionServiceHeader.Size];
                            byte[] encodedNetBiosFrame = CreateNetBiosFrame(NetBiosSessionMessageType.SessionMessage, netBiosPayload);
                            Array.Copy(encodedNetBiosFrame, partialNetBiosFrame, partialNetBiosFrame.Length);
                            bool hasNetBiosFrame = netBiosProtocol.TryReadFrame(new ReadOnlySequence<byte>(partialNetBiosFrame), out byte[]? netBiosPartialPayload, out long netBiosPartialConsumed);
                            TestAssertions.False(hasNetBiosFrame, "A partial NetBIOS frame should not decode.");
                            TestAssertions.True(netBiosPartialPayload == null, "A partial NetBIOS frame should not return a payload.");
                            TestAssertions.Equal(0L, netBiosPartialConsumed, "A partial NetBIOS frame should not consume bytes.");

                            NetBiosSessionServiceFrameProtocol constrainedNetBiosProtocol = new NetBiosSessionServiceFrameProtocol
                            {
                                MaximumFrameLength = 1024
                            };
                            byte[] oversizedNetBiosFrame = CreateNetBiosFrame(NetBiosSessionMessageType.SessionMessage, new byte[1025]);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () =>
                                {
                                    constrainedNetBiosProtocol.TryReadFrame(new ReadOnlySequence<byte>(oversizedNetBiosFrame), out byte[]? _, out long _);
                                },
                                "An oversized NetBIOS frame should fail validation.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FramedPipeConnectionTransfersFrames",
                        displayName: "Framed pipe connections transfer frames and enforce lifecycle rules",
                        executeAsync: async token =>
                        {
                            using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                            timeoutSource.CancelAfter(TimeSpan.FromSeconds(5));
                            CancellationToken timeoutToken = timeoutSource.Token;

                            Pipe inboundPipe = new Pipe();
                            Pipe outboundPipe = new Pipe();

                            await using FramedPipeConnection connection = new FramedPipeConnection(
                                inboundPipe.Reader,
                                outboundPipe.Writer,
                                new DirectTcpFrameProtocol(),
                                new FramedPipeConnectionOptions
                                {
                                    InboundFrameCapacity = 2,
                                    OutboundFrameCapacity = 2
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => connection.CompleteWrites(),
                                "Completing writes before the connection starts should fail.");

                            connection.Start();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => connection.Start(),
                                "Starting the connection twice should fail.");

                            byte[] inboundPayload = new byte[] { 0x31, 0x32, 0x33, 0x34 };
                            byte[] inboundFrame = CreateDirectTcpFrame(inboundPayload);
                            await inboundPipe.Writer.WriteAsync(inboundFrame, timeoutToken).ConfigureAwait(false);
                            await inboundPipe.Writer.CompleteAsync().ConfigureAwait(false);

                            byte[] receivedInboundPayload = await connection.ReadAsync(timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(inboundPayload, receivedInboundPayload, "The framed connection returned an unexpected inbound payload.");

                            byte[] outboundPayload = new byte[] { 0x44, 0x45, 0x46 };
                            await connection.WriteAsync(outboundPayload, timeoutToken).ConfigureAwait(false);
                            connection.CompleteWrites();

                            byte[] receivedOutboundPayload = await ReadFrameFromPipeAsync(outboundPipe.Reader, new DirectTcpFrameProtocol(), timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(outboundPayload, receivedOutboundPayload, "The framed connection wrote an unexpected outbound payload.");

                            await connection.Completion.ConfigureAwait(false);
                            await outboundPipe.Reader.CompleteAsync().ConfigureAwait(false);
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FramedPipeConnectionSuppressesExpectedSocketAbortDuringDispose",
                        displayName: "Framed pipe connections suppress expected socket-abort cleanup faults during dispose",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Pipe inboundPipe = new Pipe();
                            Pipe outboundPipe = new Pipe();

                            await using FramedPipeConnection connection = new FramedPipeConnection(
                                new ThrowingCompletePipeReader(inboundPipe.Reader),
                                new ThrowingCompletePipeWriter(outboundPipe.Writer),
                                new DirectTcpFrameProtocol());

                            connection.Start();
                            await connection.DisposeAsync().ConfigureAwait(false);
                        })
                });
        }

        private sealed class ThrowingCompletePipeReader : PipeReader
        {
            private readonly PipeReader _InnerReader;

            public ThrowingCompletePipeReader(PipeReader innerReader)
            {
                _InnerReader = innerReader ?? throw new ArgumentNullException(nameof(innerReader));
            }

            public override void AdvanceTo(SequencePosition consumed)
            {
                _InnerReader.AdvanceTo(consumed);
            }

            public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
            {
                _InnerReader.AdvanceTo(consumed, examined);
            }

            public override void CancelPendingRead()
            {
                _InnerReader.CancelPendingRead();
            }

            public override void Complete(Exception? exception = null)
            {
                throw new IOException("Simulated reader completion fault during expected cancellation.");
            }

            public override ValueTask CompleteAsync(Exception? exception = null)
            {
                return ValueTask.FromException(new IOException("Simulated reader completion fault during expected cancellation."));
            }

            public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
            {
                return _InnerReader.ReadAsync(cancellationToken);
            }

            public override bool TryRead(out ReadResult result)
            {
                return _InnerReader.TryRead(out result);
            }
        }

        private sealed class ThrowingCompletePipeWriter : PipeWriter
        {
            private readonly PipeWriter _InnerWriter;

            public ThrowingCompletePipeWriter(PipeWriter innerWriter)
            {
                _InnerWriter = innerWriter ?? throw new ArgumentNullException(nameof(innerWriter));
            }

            public override void Advance(int bytes)
            {
                _InnerWriter.Advance(bytes);
            }

            public override void CancelPendingFlush()
            {
                _InnerWriter.CancelPendingFlush();
            }

            public override void Complete(Exception? exception = null)
            {
                throw new IOException("Simulated writer completion fault during expected cancellation.");
            }

            public override ValueTask CompleteAsync(Exception? exception = null)
            {
                return ValueTask.FromException(new IOException("Simulated writer completion fault during expected cancellation."));
            }

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
            {
                return _InnerWriter.FlushAsync(cancellationToken);
            }

            public override Memory<byte> GetMemory(int sizeHint = 0)
            {
                return _InnerWriter.GetMemory(sizeHint);
            }

            public override Span<byte> GetSpan(int sizeHint = 0)
            {
                return _InnerWriter.GetSpan(sizeHint);
            }
        }    }
}

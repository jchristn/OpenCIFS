namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal static class OpenCifsClientSessionProtocolSupport
    {
        internal static SmbDialect GetMaximumImplementedDialect(bool enableSmb311Preview)
        {
            return SmbImplementationDialectPolicy.GetMaximumImplementedDialect(enableSmb311Preview);
        }

        internal static Smb2GlobalCapabilities GetNegotiationCapabilities(bool preferEncryption, IReadOnlyList<SmbDialect> advertisedDialects)
        {
            if (advertisedDialects == null)
            {
                throw new ArgumentNullException(nameof(advertisedDialects), "AdvertisedDialects cannot be null.");
            }

            if (advertisedDialects.Count == 0)
            {
                return Smb2GlobalCapabilities.None;
            }

            SmbDialect maximumDialect = advertisedDialects[advertisedDialects.Count - 1];
            Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None;

            if (maximumDialect >= SmbDialect.Smb21)
            {
                capabilities |= Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing;
            }

            if (maximumDialect >= SmbDialect.Smb30 && preferEncryption)
            {
                capabilities |= Smb2GlobalCapabilities.Encryption;
            }

            return capabilities;
        }

        internal static Smb2NegotiateContextEntry[] BuildSmb311PreviewNegotiateContextEntries(string serverName)
        {
            byte[] preauthSalt = CreateRandomBytes(32);
            byte[] preauthPayload = new PreauthIntegrityCapabilities
            {
                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                Salt = preauthSalt
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
            byte[] encryptionPayload = new EncryptionCapabilities
            {
                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes128Gcm, SmbCipherAlgorithmId.Aes128Ccm }
            }.ToByteArray();
            byte[] netnamePayload = new NetnameNegotiateContext
            {
                ServerName = serverName
            }.ToByteArray();

            return new[]
            {
                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload },
                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.Netname, Payload = netnamePayload }
            };
        }

        internal static OpenCifsClientSessionDerivedKeys DeriveAuthenticatedSessionKeys(
            byte[]? sessionBaseKey,
            SmbDialect? negotiatedDialect,
            SmbCipherAlgorithmId negotiatedCipher,
            PreauthIntegrityHashAccumulator? preauthHashAccumulator,
            Smb2SessionFlags sessionFlags)
        {
            if (sessionBaseKey == null || sessionBaseKey.Length == 0)
            {
                throw new OpenCifsClientStateException("The client does not have a session base key for the authenticated SMB session.");
            }

            bool isSessionEncryptionRequired = (sessionFlags & Smb2SessionFlags.EncryptData) != 0;

            if (!negotiatedDialect.HasValue || negotiatedDialect.Value < SmbDialect.Smb30)
            {
                return new OpenCifsClientSessionDerivedKeys(
                    isSessionEncryptionRequired,
                    (byte[])sessionBaseKey.Clone(),
                    encryptionKey: null,
                    decryptionKey: null);
            }

            SmbKeyDerivationInputs derivationInputs = new SmbKeyDerivationInputs
            {
                SessionKey = (byte[])sessionBaseKey.Clone(),
                Dialect = negotiatedDialect.Value,
                CipherAlgorithmId = negotiatedCipher
            };

            if (negotiatedDialect.Value == SmbDialect.Smb311)
            {
                if (preauthHashAccumulator == null)
                {
                    throw new OpenCifsClientStateException("SMB 3.1.1 session key derivation requires a preauthentication transcript hash.");
                }

                derivationInputs.PreauthIntegrityHash = preauthHashAccumulator.CurrentHash;
            }

            SmbSessionKeySet keySet = SmbSessionKeyDerivation.DeriveKeys(derivationInputs);

            if (isSessionEncryptionRequired)
            {
                return new OpenCifsClientSessionDerivedKeys(
                    isSessionEncryptionRequired,
                    keySet.SigningKey,
                    encryptionKey: keySet.DecryptionKey,
                    decryptionKey: keySet.EncryptionKey);
            }

            return new OpenCifsClientSessionDerivedKeys(
                isSessionEncryptionRequired,
                keySet.SigningKey,
                encryptionKey: null,
                decryptionKey: null);
        }

        internal static IMessageSigner CreateNegotiatedMessageSigner(SmbDialect? negotiatedDialect)
        {
            return MessageSignerFactory.Create(GetNegotiatedSigningAlgorithm(negotiatedDialect));
        }

        internal static NtlmNegotiateMessage CreateStandardNegotiateMessage(OpenCifsClientCredential credential)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            return new NtlmNegotiateMessage
            {
                Flags =
                    NtlmNegotiateFlags.Unicode |
                    NtlmNegotiateFlags.RequestTarget |
                    NtlmNegotiateFlags.Sign |
                    NtlmNegotiateFlags.Seal |
                    NtlmNegotiateFlags.AlwaysSign |
                    NtlmNegotiateFlags.Ntlm |
                    NtlmNegotiateFlags.ExtendedSessionSecurity |
                    NtlmNegotiateFlags.Key128 |
                    NtlmNegotiateFlags.Key56,
                DomainName = credential.UserDomain,
                Workstation = string.Empty
            };
        }

        internal static SpnegoNegTokenInit CreateInitialSessionSetupNegTokenInit(OpenCifsClientCredential credential, out byte[]? standardNegotiateMessageBytes)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            switch (credential.AuthenticationMechanism)
            {
                case OpenCifsAuthenticationMechanism.Ntlm:
                    NtlmNegotiateMessage mechanismToken = CreateStandardNegotiateMessage(credential);
                    standardNegotiateMessageBytes = mechanismToken.ToByteArray();
                    return new SpnegoNegTokenInit
                    {
                        MechanismTypes = OpenCifsAuthenticationMechanismCatalog.GetSpnegoMechanismOids(OpenCifsAuthenticationMechanism.Ntlm),
                        MechanismToken = standardNegotiateMessageBytes
                    };
                case OpenCifsAuthenticationMechanism.Kerberos:
                    standardNegotiateMessageBytes = null;
                    return new SpnegoNegTokenInit
                    {
                        MechanismTypes = OpenCifsAuthenticationMechanismCatalog.GetSpnegoMechanismOids(OpenCifsAuthenticationMechanism.Kerberos)
                    };
                default:
                    throw new OpenCifsClientStateException("The client credential requested an unsupported authentication mechanism.");
            }
        }

        internal static void ThrowKerberosNotImplemented()
        {
            throw new OpenCifsClientStateException("Kerberos session setup is not implemented yet.");
        }

        internal static NtlmV2ClientChallenge CreateStandardClientChallenge(NtlmChallengeMessage challengeMessage)
        {
            if (challengeMessage == null)
            {
                throw new ArgumentNullException(nameof(challengeMessage), "ChallengeMessage cannot be null.");
            }

            return new NtlmV2ClientChallenge
            {
                Timestamp = TryGetChallengeTimestamp(challengeMessage.TargetInfo, out ulong timestamp)
                    ? timestamp
                    : unchecked((ulong)DateTime.UtcNow.ToFileTimeUtc()),
                ClientChallenge = CreateRandomBytes(8),
                AvPairs = CloneAvPairs(challengeMessage.TargetInfo),
                TrailingBytes = new byte[4]
            };
        }

        internal static NtlmNegotiateFlags DetermineStandardAuthenticateFlags(NtlmNegotiateFlags challengeFlags)
        {
            return challengeFlags & (
                NtlmNegotiateFlags.Unicode |
                NtlmNegotiateFlags.Sign |
                NtlmNegotiateFlags.Seal |
                NtlmNegotiateFlags.Ntlm |
                NtlmNegotiateFlags.AlwaysSign |
                NtlmNegotiateFlags.ExtendedSessionSecurity |
                NtlmNegotiateFlags.Key128 |
                NtlmNegotiateFlags.Key56);
        }

        internal static bool TryExtractStandardChallengeToken(ReadOnlyMemory<byte> securityBuffer, out byte[]? challengeTokenBytes, out bool wrapAuthenticateInSpnego)
        {
            challengeTokenBytes = null;
            wrapAuthenticateInSpnego = false;

            if (StartsWithNtlmSignature(securityBuffer.Span))
            {
                challengeTokenBytes = securityBuffer.ToArray();
                return true;
            }

            SpnegoNegTokenResp responseToken;

            try
            {
                responseToken = SpnegoTokenCodec.DecodeNegTokenResp(securityBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return false;
            }

            if (responseToken.NegotiationState != SpnegoNegState.AcceptIncomplete ||
                !string.Equals(responseToken.SupportedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal) ||
                responseToken.ResponseToken == null ||
                !StartsWithNtlmSignature(responseToken.ResponseToken))
            {
                return false;
            }

            challengeTokenBytes = (byte[])responseToken.ResponseToken.Clone();
            wrapAuthenticateInSpnego = true;
            return true;
        }

        internal static byte[] CreateRandomBytes(int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");
            }

            byte[] buffer = new byte[length];
            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }

        private static SigningAlgorithmId GetNegotiatedSigningAlgorithm(SmbDialect? negotiatedDialect)
        {
            if (!negotiatedDialect.HasValue)
            {
                return SigningAlgorithmId.HmacSha256;
            }

            switch (negotiatedDialect.Value)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return SigningAlgorithmId.AesCmac;
                default:
                    return SigningAlgorithmId.HmacSha256;
            }
        }

        private static bool StartsWithNtlmSignature(ReadOnlySpan<byte> value)
        {
            ReadOnlySpan<byte> signature = "NTLMSSP\0"u8;
            return value.Length >= signature.Length && value.Slice(0, signature.Length).SequenceEqual(signature);
        }

        private static NtlmAvPair[] CloneAvPairs(IReadOnlyList<NtlmAvPair> avPairs)
        {
            if (avPairs.Count == 0)
            {
                return Array.Empty<NtlmAvPair>();
            }

            NtlmAvPair[] clonedPairs = new NtlmAvPair[avPairs.Count];

            for (int index = 0; index < avPairs.Count; index++)
            {
                clonedPairs[index] = new NtlmAvPair
                {
                    AvId = avPairs[index].AvId,
                    Value = (byte[])avPairs[index].Value.Clone()
                };
            }

            return clonedPairs;
        }

        private static bool TryGetChallengeTimestamp(IReadOnlyList<NtlmAvPair> avPairs, out ulong timestamp)
        {
            for (int index = 0; index < avPairs.Count; index++)
            {
                if (avPairs[index].AvId != NtlmAvPairId.Timestamp || avPairs[index].Value.Length != 8)
                {
                    continue;
                }

                timestamp = new LittleEndianReader(avPairs[index].Value).ReadUInt64();
                return true;
            }

            timestamp = 0;
            return false;
        }
    }
}

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.Security.Cryptography;
    using System.Text;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsServerSessionSetupSupport
    {
        private readonly IReadOnlyDictionary<string, OpenCifsServerAccount> _Accounts;
        private readonly string _ServerName;
        private readonly string[] _SupportedSpnegoMechanisms;

        public OpenCifsServerSessionSetupSupport(IReadOnlyDictionary<string, OpenCifsServerAccount> accounts, string serverName, OpenCifsAuthenticationMechanism authenticationMechanism = OpenCifsAuthenticationMechanism.Ntlm)
        {
            _Accounts = accounts ?? throw new ArgumentNullException(nameof(accounts), "Accounts cannot be null.");
            _ServerName = !string.IsNullOrWhiteSpace(serverName)
                ? serverName
                : throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            _SupportedSpnegoMechanisms = OpenCifsAuthenticationMechanismCatalog.GetSpnegoMechanismOids(authenticationMechanism);
        }

        public static string GetAccountKey(string userName, string userDomain)
        {
            return userName + "|" + userDomain;
        }

        public bool TryGetAccount(string userName, string userDomain, out OpenCifsServerAccount? account)
        {
            return _Accounts.TryGetValue(GetAccountKey(userName, userDomain), out account);
        }

        public string DetermineChallengeTargetDomain()
        {
            string? expectedDomain = null;

            foreach (KeyValuePair<string, OpenCifsServerAccount> accountEntry in _Accounts)
            {
                string candidateDomain = accountEntry.Value.UserDomain;

                if (string.IsNullOrWhiteSpace(candidateDomain))
                {
                    continue;
                }

                if (expectedDomain == null)
                {
                    expectedDomain = candidateDomain;
                    continue;
                }

                if (!string.Equals(expectedDomain, candidateDomain, StringComparison.OrdinalIgnoreCase))
                {
                    return _ServerName;
                }
            }

            return expectedDomain ?? _ServerName;
        }

        public bool TryParseInitialSessionSetupToken(ReadOnlyMemory<byte> securityBuffer, out InitialSessionSetupToken? token, out NtStatus status)
        {
            token = null;
            status = NtStatus.InvalidParameter;

            if (StartsWithNtlmSignature(securityBuffer))
            {
                if (Array.IndexOf(_SupportedSpnegoMechanisms, SpnegoMechanismOid.Ntlm) < 0)
                {
                    status = NtStatus.NotSupported;
                    return false;
                }

                try
                {
                    token = new InitialSessionSetupToken
                    {
                        Flavor = SessionSetupFlavor.RawNtlm,
                        StandardNegotiateMessageBytes = securityBuffer.ToArray(),
                        StandardNegotiateMessage = NtlmNegotiateMessage.ReadFrom(securityBuffer)
                    };
                    status = NtStatus.Success;
                    return true;
                }
                catch (ProtocolEncodingException)
                {
                    return false;
                }
            }

            SpnegoNegTokenInit initToken;

            try
            {
                initToken = SpnegoTokenCodec.DecodeNegTokenInit(securityBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return false;
            }

            bool selected = SpnegoMechanismNegotiator.TrySelectMechanism(
                request: initToken,
                supportedMechanisms: _SupportedSpnegoMechanisms,
                selectedMechanism: out string? selectedMechanism);

            if (!selected || string.IsNullOrWhiteSpace(selectedMechanism))
            {
                status = NtStatus.NotSupported;
                return false;
            }

            if (OpenCifsAuthenticationMechanismCatalog.IsKerberosMechanismOid(selectedMechanism))
            {
                token = new InitialSessionSetupToken
                {
                    Flavor = SessionSetupFlavor.SpnegoKerberos,
                    SpnegoInitToken = initToken,
                    SelectedMechanismOid = selectedMechanism
                };
                status = NtStatus.Success;
                return true;
            }

            if (!string.Equals(selectedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
            {
                status = NtStatus.NotSupported;
                return false;
            }

            if (initToken.MechanismToken == null)
            {
                return false;
            }

            if (StartsWithNtlmSignature(initToken.MechanismToken))
            {
                try
                {
                    token = new InitialSessionSetupToken
                    {
                        Flavor = SessionSetupFlavor.SpnegoNtlm,
                        SpnegoInitToken = initToken,
                        SelectedMechanismOid = selectedMechanism,
                        StandardNegotiateMessageBytes = (byte[])initToken.MechanismToken.Clone(),
                        StandardNegotiateMessage = NtlmNegotiateMessage.ReadFrom(initToken.MechanismToken)
                    };
                    status = NtStatus.Success;
                    return true;
                }
                catch (ProtocolEncodingException)
                {
                    return false;
                }
            }

            try
            {
                token = new InitialSessionSetupToken
                {
                    Flavor = SessionSetupFlavor.LegacyOpenCifs,
                    SpnegoInitToken = initToken,
                    SelectedMechanismOid = selectedMechanism,
                    LegacyNegotiateToken = OpenCifsNtlmNegotiateToken.ReadFrom(initToken.MechanismToken)
                };
                status = NtStatus.Success;
                return true;
            }
            catch (ProtocolEncodingException)
            {
                return false;
            }
        }

        public static bool TryExtractStandardAuthenticateToken(ReadOnlyMemory<byte> securityBuffer, SessionSetupFlavor flavor, out byte[]? authenticateBytes, out NtStatus status)
        {
            authenticateBytes = null;
            status = NtStatus.InvalidParameter;

            if (flavor == SessionSetupFlavor.RawNtlm)
            {
                if (!StartsWithNtlmSignature(securityBuffer))
                {
                    return false;
                }

                authenticateBytes = securityBuffer.ToArray();
                status = NtStatus.Success;
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

            if (responseToken.ResponseToken == null || !StartsWithNtlmSignature(responseToken.ResponseToken))
            {
                return false;
            }

            authenticateBytes = (byte[])responseToken.ResponseToken.Clone();
            status = NtStatus.Success;
            return true;
        }

        public static NtlmChallengeMessage CreateStandardChallengeMessage(NtlmNegotiateMessage negotiateMessage, byte[] serverChallenge, string expectedServerName, string expectedUserDomain)
        {
            NtlmNegotiateFlags flags = negotiateMessage.Flags |
                NtlmNegotiateFlags.RequestTarget |
                NtlmNegotiateFlags.Ntlm |
                NtlmNegotiateFlags.AlwaysSign |
                NtlmNegotiateFlags.TargetInfo |
                NtlmNegotiateFlags.TargetTypeServer;

            if ((flags & NtlmNegotiateFlags.Unicode) != 0)
            {
                flags &= ~NtlmNegotiateFlags.Oem;
            }
            else if ((flags & NtlmNegotiateFlags.Oem) == 0)
            {
                throw new ProtocolEncodingException("The NTLM negotiate message did not advertise a supported text encoding.");
            }

            if ((flags & NtlmNegotiateFlags.ExtendedSessionSecurity) != 0)
            {
                flags &= ~NtlmNegotiateFlags.LmKey;
            }

            LittleEndianWriter timestampWriter = new LittleEndianWriter();
            timestampWriter.WriteUInt64(unchecked((ulong)DateTimeOffset.UtcNow.UtcDateTime.ToFileTimeUtc()));

            return new NtlmChallengeMessage
            {
                Flags = flags,
                ServerChallenge = serverChallenge,
                TargetName = expectedServerName,
                TargetInfo = new NtlmAvPair[]
                {
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosComputerName,
                        Value = Encoding.Unicode.GetBytes(expectedServerName)
                    },
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosDomainName,
                        Value = Encoding.Unicode.GetBytes(expectedUserDomain)
                    },
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.Timestamp,
                        Value = timestampWriter.ToArray()
                    }
                }
            };
        }

        public static bool ValidateAuthenticateTokenTargetInfo(OpenCifsNtlmAuthenticateToken authenticateToken, string expectedServerName, string expectedUserDomain)
        {
            return ValidateAuthenticateTokenTargetInfo(authenticateToken.NtChallengeResponse, expectedServerName, expectedUserDomain);
        }

        public static bool ValidateAuthenticateTokenTargetInfo(ReadOnlySpan<byte> ntChallengeResponse, string expectedServerName, string expectedUserDomain)
        {
            try
            {
                NtlmV2Response ntlmResponse = NtlmV2Response.ReadFrom(ntChallengeResponse.ToArray());
                string actualServerName = string.Empty;
                string actualDomainName = string.Empty;

                for (int index = 0; index < ntlmResponse.ClientChallenge.AvPairs.Length; index++)
                {
                    NtlmAvPair avPair = ntlmResponse.ClientChallenge.AvPairs[index];

                    if (avPair.AvId == NtlmAvPairId.NetBiosComputerName)
                    {
                        actualServerName = Encoding.Unicode.GetString(avPair.Value);
                    }
                    else if (avPair.AvId == NtlmAvPairId.NetBiosDomainName)
                    {
                        actualDomainName = Encoding.Unicode.GetString(avPair.Value);
                    }
                }

                return string.Equals(actualServerName, expectedServerName, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(actualDomainName, expectedUserDomain, StringComparison.OrdinalIgnoreCase);
            }
            catch (ProtocolEncodingException)
            {
                return false;
            }
        }

        public static byte[] ComputeSpnegoMechanismListMic(IReadOnlyList<string> mechanismTypes, NtlmNegotiateFlags flags, ReadOnlySpan<byte> sessionKey)
        {
            if (mechanismTypes == null)
            {
                throw new ArgumentNullException(nameof(mechanismTypes), "MechanismTypes cannot be null.");
            }

            if (mechanismTypes.Count == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(mechanismTypes), "At least one SPNEGO mechanism type is required.");
            }

            if (sessionKey.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sessionKey), "The exported NTLM session key cannot be empty.");
            }

            byte[] mechanismTypeList = EncodeSpnegoMechanismTypeList(mechanismTypes);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(0);
            writer.WriteBytes(mechanismTypeList);
            byte[] checksum = HmacMd5.HashData(
                CreateNtlmSigningKey(flags, sessionKey, serverToClient: true),
                writer.ToArray());

            if ((flags & NtlmNegotiateFlags.KeyExchange) != 0)
            {
                checksum = Rc4.Transform(
                    CreateNtlmSealingKey(flags, sessionKey, serverToClient: true),
                    checksum.AsSpan(0, 8));
            }

            LittleEndianWriter signatureWriter = new LittleEndianWriter();
            signatureWriter.WriteUInt32(1);
            signatureWriter.WriteBytes(checksum.AsSpan(0, 8));
            signatureWriter.WriteUInt32(0);
            return signatureWriter.ToArray();
        }

        private static bool StartsWithNtlmSignature(ReadOnlyMemory<byte> token)
        {
            ReadOnlySpan<byte> span = token.Span;
            ReadOnlySpan<byte> signature = "NTLMSSP\0"u8;
            return span.Length >= signature.Length && span.Slice(0, signature.Length).SequenceEqual(signature);
        }

        private static byte[] EncodeSpnegoMechanismTypeList(IReadOnlyList<string> mechanismTypes)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            for (int index = 0; index < mechanismTypes.Count; index++)
            {
                if (string.IsNullOrWhiteSpace(mechanismTypes[index]))
                {
                    throw new ArgumentException("MechanismTypes cannot contain null or whitespace entries.", nameof(mechanismTypes));
                }

                writer.WriteObjectIdentifier(mechanismTypes[index]);
            }

            writer.PopSequence();
            return writer.Encode();
        }

        private static byte[] CreateNtlmSigningKey(NtlmNegotiateFlags flags, ReadOnlySpan<byte> sessionKey, bool serverToClient)
        {
            if ((flags & NtlmNegotiateFlags.ExtendedSessionSecurity) == 0)
            {
                if ((flags & NtlmNegotiateFlags.AlwaysSign) != 0)
                {
                    return Array.Empty<byte>();
                }

                throw new NotSupportedException("The bounded SPNEGO mechListMIC helper requires NTLM extended session security.");
            }

            string direction = serverToClient ? "server-to-client" : "client-to-server";
            byte[] suffix = Encoding.ASCII.GetBytes("session key to " + direction + " signing key magic constant\0");
            byte[] material = new byte[sessionKey.Length + suffix.Length];
            sessionKey.CopyTo(material);
            suffix.CopyTo(material.AsSpan(sessionKey.Length));
            return MD5.HashData(material);
        }

        private static byte[] CreateNtlmSealingKey(NtlmNegotiateFlags flags, ReadOnlySpan<byte> sessionKey, bool serverToClient)
        {
            ReadOnlySpan<byte> baseSealKey;

            if ((flags & NtlmNegotiateFlags.ExtendedSessionSecurity) != 0)
            {
                if ((flags & NtlmNegotiateFlags.Key128) != 0)
                {
                    baseSealKey = sessionKey;
                }
                else if ((flags & NtlmNegotiateFlags.Key56) != 0)
                {
                    baseSealKey = sessionKey.Slice(0, Math.Min(7, sessionKey.Length));
                }
                else
                {
                    baseSealKey = sessionKey.Slice(0, Math.Min(5, sessionKey.Length));
                }

                string direction = serverToClient ? "server-to-client" : "client-to-server";
                byte[] material = new byte[baseSealKey.Length + ("session key to " + direction + " sealing key magic constant\0").Length];
                baseSealKey.CopyTo(material);
                Encoding.ASCII.GetBytes("session key to " + direction + " sealing key magic constant\0").CopyTo(material.AsSpan(baseSealKey.Length));
                return MD5.HashData(material);
            }

            throw new NotSupportedException("The bounded SPNEGO mechListMIC helper requires NTLM extended session security.");
        }
    }
}

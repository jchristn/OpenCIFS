namespace OpenCIFS.Client
{
    using System;
    using System.Text;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsClientSessionBootstrapService
    {
        public OpenCifsClientSessionBootstrapService(
            OpenCifsClientOptions options,
            Guid clientGuid,
            ConnectionState connectionState,
            OpenCifsClientSessionBootstrapState state,
            Action resetAuthenticatedState)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _ClientGuid = clientGuid;
            _ConnectionState = connectionState ?? throw new ArgumentNullException(nameof(connectionState), "ConnectionState cannot be null.");
            _State = state ?? throw new ArgumentNullException(nameof(state), "State cannot be null.");
            _ResetAuthenticatedState = resetAuthenticatedState ?? throw new ArgumentNullException(nameof(resetAuthenticatedState), "ResetAuthenticatedState cannot be null.");
        }

        public SmbDialect[] GetAdvertisedDialects()
        {
            SmbDialect maximumImplementedDialect = OpenCifsClientSessionProtocolSupport.GetMaximumImplementedDialect(_Options.EnableSmb311Preview);
            SmbDialect effectiveMaximumDialect = _Options.MaximumDialect < maximumImplementedDialect
                ? _Options.MaximumDialect
                : maximumImplementedDialect;

            if (effectiveMaximumDialect < _Options.MinimumDialect)
            {
                return Array.Empty<SmbDialect>();
            }

            return SmbDialectCatalog.GetSmb2DialectsInRange(_Options.MinimumDialect, effectiveMaximumDialect);
        }

        public Smb2NegotiateRequest CreateNegotiateRequest()
        {
            SmbDialect[] advertisedDialects = GetAdvertisedDialects();

            if (advertisedDialects.Length == 0)
            {
                throw new OpenCifsClientStateException("The configured client dialect range does not include any currently implemented SMB2 dialects.");
            }

            Smb2SecurityMode securityMode = Smb2SecurityMode.SigningEnabled;

            if (_Options.RequireSigning)
            {
                securityMode |= Smb2SecurityMode.SigningRequired;
            }

            Smb2NegotiateRequest request = new Smb2NegotiateRequest
            {
                SecurityMode = securityMode,
                Capabilities = OpenCifsClientSessionProtocolSupport.GetNegotiationCapabilities(_Options.PreferEncryption, advertisedDialects),
                ClientGuid = _ClientGuid,
                ClientStartTime = 0,
                Dialects = advertisedDialects
            };

            if (_Options.EnableSmb311Preview && Array.IndexOf(advertisedDialects, SmbDialect.Smb311) >= 0)
            {
                request.SetNegotiateContextEntries(OpenCifsClientSessionProtocolSupport.BuildSmb311PreviewNegotiateContextEntries(_Options.ServerName));
                _State.PreauthHashAccumulator = new PreauthIntegrityHashAccumulator(HashAlgorithmId.Sha512);
            }
            else
            {
                _State.PreauthHashAccumulator = null;
            }

            Smb2NegotiateRequestValidator.Validate(request);
            _State.LastOfferedDialects = advertisedDialects;
            _State.NegotiatedClientSecurityMode = request.SecurityMode;
            _State.NegotiatedClientCapabilities = request.Capabilities;
            _State.IsSecureNegotiateValidated = false;
            return request;
        }

        public void AppendPreauthMessageBytes(Smb2Header header, byte[] body)
        {
            if (_State.PreauthHashAccumulator == null)
            {
                return;
            }

            if (header == null)
            {
                throw new ArgumentNullException(nameof(header), "Header cannot be null.");
            }

            if (body == null)
            {
                throw new ArgumentNullException(nameof(body), "Body cannot be null.");
            }

            byte[] headerBytes = header.ToByteArray();
            byte[] message = new byte[headerBytes.Length + body.Length];
            Buffer.BlockCopy(headerBytes, 0, message, 0, headerBytes.Length);
            Buffer.BlockCopy(body, 0, message, headerBytes.Length, body.Length);
            _State.PreauthHashAccumulator.Append(message);
        }

        public byte[]? GetCurrentPreauthIntegrityHash()
        {
            return _State.PreauthHashAccumulator?.CurrentHash;
        }

        public void ApplyNegotiateResponse(Smb2NegotiateResponse response)
        {
            if (_State.LastOfferedDialects == null)
            {
                throw new OpenCifsClientStateException("A negotiate request must be created before a response can be applied.");
            }

            Smb2NegotiateResponseValidator.Validate(response);

            if (!ContainsDialect(_State.LastOfferedDialects, response.Dialect))
            {
                throw new OpenCifsClientStateException("The server selected a dialect that the client did not advertise.");
            }

            if (response.Dialect < _Options.MinimumDialect || response.Dialect > _Options.MaximumDialect)
            {
                throw new OpenCifsClientStateException("The negotiated dialect is outside the configured client dialect range.");
            }

            if ((response.SecurityMode & Smb2SecurityMode.SigningEnabled) == 0)
            {
                throw new OpenCifsClientStateException("The server negotiate response must enable message signing.");
            }

            _State.NegotiatedDialect = response.Dialect;
            _State.ServerGuid = response.ServerGuid;
            _State.NegotiatedMaxTransactSize = response.MaxTransactSize;
            _State.NegotiatedMaxReadSize = response.MaxReadSize;
            _State.NegotiatedMaxWriteSize = response.MaxWriteSize;
            _State.NegotiatedServerCapabilities = response.Capabilities;
            _State.NegotiatedServerSecurityMode = response.SecurityMode;
            _State.IsSigningRequired = _Options.RequireSigning || (response.SecurityMode & Smb2SecurityMode.SigningRequired) != 0;
            _State.IsSecureNegotiateValidated = false;
            _State.NegotiatedCipher = SmbCipherAlgorithmId.Aes128Ccm;

            if (response.Dialect == SmbDialect.Smb311)
            {
                if (response.NegotiateContextCount == 0)
                {
                    throw new OpenCifsClientStateException("The SMB 3.1.1 server negotiate response must carry at least one negotiate-context entry.");
                }

                Smb2NegotiateContextEntry[] responseEntries = response.DecodeNegotiateContextEntries();
                bool sawPreauthContext = false;

                for (int index = 0; index < responseEntries.Length; index++)
                {
                    Smb2NegotiateContextEntry entry = responseEntries[index];

                    if (entry.ContextType == Smb2NegotiateContextType.PreauthIntegrityCapabilities)
                    {
                        PreauthIntegrityCapabilities serverPreauth = PreauthIntegrityCapabilities.ReadFrom(entry.Payload);

                        if (serverPreauth.HashAlgorithms.Length != 1)
                        {
                            throw new OpenCifsClientStateException("The SMB 3.1.1 server response must select exactly one preauth integrity hash algorithm.");
                        }

                        if (serverPreauth.HashAlgorithms[0] != HashAlgorithmId.Sha512)
                        {
                            throw new OpenCifsClientStateException("The SMB 3.1.1 server selected a preauth integrity hash algorithm that is not supported by the bounded preview slice.");
                        }

                        sawPreauthContext = true;
                        continue;
                    }

                    if (entry.ContextType == Smb2NegotiateContextType.EncryptionCapabilities)
                    {
                        EncryptionCapabilities serverEncryption = EncryptionCapabilities.ReadFrom(entry.Payload);

                        if (serverEncryption.Ciphers.Length != 1)
                        {
                            throw new OpenCifsClientStateException("The SMB 3.1.1 server response must select exactly one encryption cipher.");
                        }

                        SmbCipherAlgorithmId serverSelected = serverEncryption.Ciphers[0];

                        if (serverSelected != SmbCipherAlgorithmId.Aes128Ccm && serverSelected != SmbCipherAlgorithmId.Aes128Gcm)
                        {
                            throw new OpenCifsClientStateException("The SMB 3.1.1 server selected an encryption cipher that is not supported by the bounded preview slice.");
                        }

                        _State.NegotiatedCipher = serverSelected;
                        continue;
                    }
                }

                if (!sawPreauthContext)
                {
                    throw new OpenCifsClientStateException("The SMB 3.1.1 server negotiate response must carry a preauth integrity context.");
                }
            }

            _ConnectionState.Negotiate(response.Dialect);
        }

        public Smb2SessionSetupRequest CreateSessionSetupRequest(OpenCifsClientCredential credential)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            if (!_State.NegotiatedDialect.HasValue)
            {
                throw new OpenCifsClientStateException("Negotiate must complete before session setup can begin.");
            }

            SpnegoNegTokenInit initToken = OpenCifsClientSessionProtocolSupport.CreateInitialSessionSetupNegTokenInit(credential, out byte[]? negotiateMessageBytes);
            _State.StandardNegotiateMessage = negotiateMessageBytes == null
                ? null
                : (byte[])negotiateMessageBytes.Clone();

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                Flags = 0,
                SecurityMode = _State.IsSigningRequired
                    ? (Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)
                    : Smb2SecurityMode.SigningEnabled,
                Capabilities = Smb2GlobalCapabilities.None,
                Channel = 0,
                PreviousSessionId = 0,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(initToken)
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        public Smb2SessionSetupRequest CreateSessionAuthenticateRequest(
            OpenCifsClientCredential credential,
            ulong sessionId,
            NtStatus status,
            Smb2SessionSetupResponse challengeResponse)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            if (!_State.NegotiatedDialect.HasValue)
            {
                throw new OpenCifsClientStateException("Negotiate must complete before session authentication can continue.");
            }

            if (status != NtStatus.MoreProcessingRequired)
            {
                throw new OpenCifsClientStateException("The server did not return an SMB2 session-setup challenge.");
            }

            if (challengeResponse == null)
            {
                throw new ArgumentNullException(nameof(challengeResponse), "ChallengeResponse cannot be null.");
            }

            Smb2SessionSetupResponseValidator.Validate(challengeResponse);

            if (sessionId == 0)
            {
                throw new OpenCifsClientStateException("The server challenge did not include a valid session identifier.");
            }

            if (challengeResponse.SecurityBuffer.Length == 0)
            {
                throw new OpenCifsClientStateException("The server challenge did not include a security buffer.");
            }

            if (credential.AuthenticationMechanism == OpenCifsAuthenticationMechanism.Kerberos)
            {
                OpenCifsClientSessionProtocolSupport.ThrowKerberosNotImplemented();
            }

            if (OpenCifsClientSessionProtocolSupport.TryExtractStandardChallengeToken(challengeResponse.SecurityBuffer, out byte[]? challengeTokenBytes, out bool wrapAuthenticateInSpnego) &&
                challengeTokenBytes != null)
            {
                NtlmChallengeMessage challengeMessage;

                try
                {
                    challengeMessage = NtlmChallengeMessage.ReadFrom(challengeTokenBytes);
                }
                catch (ProtocolEncodingException exception)
                {
                    throw new OpenCifsClientProtocolException("The server challenge token is not a valid NTLM challenge message.", exception);
                }

                if (_State.StandardNegotiateMessage == null || _State.StandardNegotiateMessage.Length == 0)
                {
                    throw new OpenCifsClientStateException("The client does not have the original NTLM negotiate message for session authentication.");
                }

                NtlmV2ClientChallenge clientChallenge = OpenCifsClientSessionProtocolSupport.CreateStandardClientChallenge(challengeMessage);
                NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                    password: credential.Password,
                    userName: credential.UserName,
                    userDomain: credential.UserDomain,
                    serverChallenge: challengeMessage.ServerChallenge,
                    clientChallenge: clientChallenge);

                _State.SessionBaseKey = responseSet.SessionBaseKey;
                _State.SessionSigningKey = responseSet.SessionBaseKey;
                _State.SessionId = sessionId;

                NtlmAuthenticateMessage standardAuthenticateToken = new NtlmAuthenticateMessage
                {
                    Flags = OpenCifsClientSessionProtocolSupport.DetermineStandardAuthenticateFlags(challengeMessage.Flags),
                    LmChallengeResponse = responseSet.LmChallengeResponse,
                    NtChallengeResponse = responseSet.NtChallengeResponse.ToByteArray(),
                    DomainName = credential.UserDomain,
                    UserName = credential.UserName,
                    Workstation = string.Empty,
                    IncludeMessageIntegrityCodeField = true
                };
                byte[] authenticateTokenBytesWithZeroMic = standardAuthenticateToken.ToByteArray(zeroMessageIntegrityCode: true);
                standardAuthenticateToken.MessageIntegrityCode = NtlmMessageIntegrityCode.Compute(
                    exportedSessionKey: responseSet.SessionBaseKey,
                    negotiateMessage: _State.StandardNegotiateMessage,
                    challengeMessage: challengeTokenBytes,
                    authenticateMessageWithZeroMic: authenticateTokenBytesWithZeroMic);
                byte[] authenticateTokenBytes = standardAuthenticateToken.ToByteArray();

                Smb2SessionSetupRequest standardRequest = new Smb2SessionSetupRequest
                {
                    Flags = 0,
                    SecurityMode = _State.IsSigningRequired
                        ? (Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)
                        : Smb2SecurityMode.SigningEnabled,
                    Capabilities = Smb2GlobalCapabilities.None,
                    Channel = 0,
                    PreviousSessionId = 0,
                    SecurityBuffer = wrapAuthenticateInSpnego
                        ? SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                        {
                            ResponseToken = authenticateTokenBytes
                        })
                        : authenticateTokenBytes
                };

                Smb2SessionSetupRequestValidator.Validate(standardRequest);
                return standardRequest;
            }

            SpnegoNegTokenResp responseToken;

            try
            {
                responseToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResponse.SecurityBuffer);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new OpenCifsClientProtocolException("The server challenge security buffer is not a valid SPNEGO response token.", exception);
            }

            if (responseToken.NegotiationState != SpnegoNegState.AcceptIncomplete)
            {
                throw new OpenCifsClientStateException("The server challenge must report an incomplete SPNEGO negotiation state.");
            }

            if (!string.Equals(responseToken.SupportedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
            {
                throw new OpenCifsClientStateException("The server selected an unsupported SPNEGO mechanism.");
            }

            if (responseToken.ResponseToken == null)
            {
                throw new OpenCifsClientStateException("The server challenge is missing the NTLM response token.");
            }

            OpenCifsNtlmChallengeToken legacyChallengeToken;

            try
            {
                legacyChallengeToken = OpenCifsNtlmChallengeToken.ReadFrom(responseToken.ResponseToken);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new OpenCifsClientProtocolException("The server challenge token is not a valid OpenCIFS NTLM challenge token.", exception);
            }

            NtlmV2ClientChallenge legacyClientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = unchecked((ulong)DateTime.UtcNow.ToFileTimeUtc()),
                ClientChallenge = OpenCifsClientSessionProtocolSupport.CreateRandomBytes(8),
                AvPairs = new NtlmAvPair[]
                {
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosDomainName,
                        Value = Encoding.Unicode.GetBytes(legacyChallengeToken.TargetDomain)
                    },
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosComputerName,
                        Value = Encoding.Unicode.GetBytes(legacyChallengeToken.ServerName)
                    }
                },
                TrailingBytes = new byte[4]
            };

            NtlmV2ChallengeResponseSet legacyResponseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                password: credential.Password,
                userName: credential.UserName,
                userDomain: credential.UserDomain,
                serverChallenge: legacyChallengeToken.ServerChallenge,
                clientChallenge: legacyClientChallenge);

            _State.SessionBaseKey = legacyResponseSet.SessionBaseKey;
            _State.SessionSigningKey = legacyResponseSet.SessionBaseKey;
            _State.SessionId = sessionId;

            OpenCifsNtlmAuthenticateToken authenticateToken = new OpenCifsNtlmAuthenticateToken
            {
                UserName = credential.UserName,
                UserDomain = credential.UserDomain,
                NtChallengeResponse = legacyResponseSet.NtChallengeResponse.ToByteArray(),
                LmChallengeResponse = legacyResponseSet.LmChallengeResponse
            };

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                Flags = 0,
                SecurityMode = _State.IsSigningRequired
                    ? (Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)
                    : Smb2SecurityMode.SigningEnabled,
                Capabilities = Smb2GlobalCapabilities.None,
                Channel = 0,
                PreviousSessionId = 0,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    ResponseToken = authenticateToken.ToByteArray()
                })
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        public void ApplySessionSetupResult(ulong sessionId, NtStatus status, Smb2SessionSetupResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.SessionSetup, status);
            }

            if (_State.SessionBaseKey == null || _State.SessionBaseKey.Length == 0)
            {
                throw new OpenCifsClientStateException("The client does not have a session base key for the authenticated session.");
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2SessionSetupResponseValidator.Validate(response);

            if (sessionId == 0)
            {
                throw new OpenCifsClientStateException("The server did not return a valid session identifier.");
            }

            if (response.SecurityBuffer.Length > 0)
            {
                SpnegoNegTokenResp responseToken;

                try
                {
                    responseToken = SpnegoTokenCodec.DecodeNegTokenResp(response.SecurityBuffer);
                }
                catch (ProtocolEncodingException exception)
                {
                    throw new OpenCifsClientProtocolException("The server session-setup response is not a valid SPNEGO response token.", exception);
                }

                if (responseToken.NegotiationState != SpnegoNegState.AcceptCompleted)
                {
                    throw new OpenCifsClientStateException("The server session-setup response did not complete SPNEGO negotiation.");
                }

                if (!string.IsNullOrEmpty(responseToken.SupportedMechanism) &&
                    !string.Equals(responseToken.SupportedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
                {
                    throw new OpenCifsClientStateException("The server completed session setup with an unsupported mechanism.");
                }
            }

            if (_State.SessionState.SessionId == 0)
            {
                _State.SessionState.Bind(sessionId);
            }

            _State.SessionState.Authenticate();
            _State.SessionId = sessionId;
            ApplyAuthenticatedSessionKeys(response.SessionFlags);
        }

        public Smb2EchoRequest CreateEchoRequest()
        {
            if (!_State.SessionState.IsAuthenticated || _State.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated session is required before echo.");
            }

            Smb2EchoRequest request = new Smb2EchoRequest();
            Smb2EchoRequestValidator.Validate(request);
            return request;
        }

        public void ApplyEchoResult(NtStatus status, Smb2EchoResponse response)
        {
            if (!_State.SessionState.IsAuthenticated || _State.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated session is required before echo responses can be applied.");
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Echo, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2EchoResponseValidator.Validate(response);
        }

        public Smb2LogoffRequest CreateLogoffRequest()
        {
            if (!_State.SessionState.IsAuthenticated || _State.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated session is required before logoff.");
            }

            Smb2LogoffRequest request = new Smb2LogoffRequest();
            Smb2LogoffRequestValidator.Validate(request);
            return request;
        }

        public void ApplyLogoffResult(NtStatus status, Smb2LogoffResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Logoff, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2LogoffResponseValidator.Validate(response);
            _ResetAuthenticatedState();
        }

        private void ApplyAuthenticatedSessionKeys(Smb2SessionFlags sessionFlags)
        {
            OpenCifsClientSessionDerivedKeys derivedKeys = OpenCifsClientSessionProtocolSupport.DeriveAuthenticatedSessionKeys(
                _State.SessionBaseKey,
                _State.NegotiatedDialect,
                _State.NegotiatedCipher,
                _State.PreauthHashAccumulator,
                sessionFlags);

            _State.IsSessionEncryptionRequired = derivedKeys.IsSessionEncryptionRequired;
            _State.SessionSigningKey = derivedKeys.SigningKey;
            _State.SessionEncryptionKey = derivedKeys.EncryptionKey;
            _State.SessionDecryptionKey = derivedKeys.DecryptionKey;
        }

        private static bool ContainsDialect(ReadOnlySpan<SmbDialect> dialects, SmbDialect dialect)
        {
            for (int index = 0; index < dialects.Length; index++)
            {
                if (dialects[index] == dialect)
                {
                    return true;
                }
            }

            return false;
        }

        private readonly OpenCifsClientOptions _Options;
        private readonly Guid _ClientGuid;
        private readonly ConnectionState _ConnectionState;
        private readonly OpenCifsClientSessionBootstrapState _State;
        private readonly Action _ResetAuthenticatedState;
    }
}

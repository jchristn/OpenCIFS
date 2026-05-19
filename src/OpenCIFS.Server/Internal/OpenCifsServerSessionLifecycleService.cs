namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsServerSessionLifecycleService
    {
        private readonly Func<ulong> _AllocateSessionId;
        private readonly Action<ServerSessionRecord> _CleanupSessionRecord;
        private readonly IReadOnlyDictionary<ulong, ServerSessionRecord> _ReadOnlySessions;
        private readonly Dictionary<ulong, ServerSessionRecord> _Sessions;
        private readonly OpenCifsServerSessionSecurityService _SessionSecurityService;
        private readonly OpenCifsServerSessionSetupSupport _SessionSetupSupport;
        private readonly Action<ulong, ServerSessionRecord> _RetainResponseEncryptionKey;
        private readonly Action<ulong, ServerSessionRecord> _RetainResponseSigningKey;
        private readonly string _ServerName;
        private readonly Func<ulong, string, string, SessionSetupFlavor, NtStatus?> _InvokeAuthenticatedSessionCallback;
        private readonly Action<string> _WriteDiagnostic;

        public OpenCifsServerSessionLifecycleService(
            Dictionary<ulong, ServerSessionRecord> sessions,
            string serverName,
            OpenCifsServerSessionSetupSupport sessionSetupSupport,
            OpenCifsServerSessionSecurityService sessionSecurityService,
            Func<ulong> allocateSessionId,
            Action<ServerSessionRecord> cleanupSessionRecord,
            Action<ulong, ServerSessionRecord> retainResponseSigningKey,
            Action<ulong, ServerSessionRecord> retainResponseEncryptionKey,
            Func<ulong, string, string, SessionSetupFlavor, NtStatus?> invokeAuthenticatedSessionCallback,
            Action<string> writeDiagnostic)
        {
            _Sessions = sessions ?? throw new ArgumentNullException(nameof(sessions), "Sessions cannot be null.");
            _ReadOnlySessions = _Sessions;
            _ServerName = !string.IsNullOrWhiteSpace(serverName)
                ? serverName
                : throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            _SessionSetupSupport = sessionSetupSupport ?? throw new ArgumentNullException(nameof(sessionSetupSupport), "SessionSetupSupport cannot be null.");
            _SessionSecurityService = sessionSecurityService ?? throw new ArgumentNullException(nameof(sessionSecurityService), "SessionSecurityService cannot be null.");
            _AllocateSessionId = allocateSessionId ?? throw new ArgumentNullException(nameof(allocateSessionId), "AllocateSessionId cannot be null.");
            _CleanupSessionRecord = cleanupSessionRecord ?? throw new ArgumentNullException(nameof(cleanupSessionRecord), "CleanupSessionRecord cannot be null.");
            _RetainResponseSigningKey = retainResponseSigningKey ?? throw new ArgumentNullException(nameof(retainResponseSigningKey), "RetainResponseSigningKey cannot be null.");
            _RetainResponseEncryptionKey = retainResponseEncryptionKey ?? throw new ArgumentNullException(nameof(retainResponseEncryptionKey), "RetainResponseEncryptionKey cannot be null.");
            _InvokeAuthenticatedSessionCallback = invokeAuthenticatedSessionCallback ?? throw new ArgumentNullException(nameof(invokeAuthenticatedSessionCallback), "InvokeAuthenticatedSessionCallback cannot be null.");
            _WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException(nameof(writeDiagnostic), "WriteDiagnostic cannot be null.");
        }

        public OpenCifsServerSessionSetupResult HandleSessionSetup(ulong sessionId, Smb2SessionSetupRequest request)
        {
            Smb2SessionSetupRequestValidator.Validate(request);

            if (sessionId == 0)
            {
                return BeginSessionSetup(request);
            }

            return CompleteSessionSetup(sessionId, request);
        }

        public OpenCifsServerOperationResult<Smb2LogoffResponse> HandleLogoff(ulong sessionId, Smb2LogoffRequest request)
        {
            Smb2LogoffRequestValidator.Validate(request);

            if (!_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2LogoffResponse());
            }

            _RetainResponseSigningKey(sessionId, sessionRecord);
            _RetainResponseEncryptionKey(sessionId, sessionRecord);
            _CleanupSessionRecord(sessionRecord);
            _Sessions.Remove(sessionId);

            Smb2LogoffResponse response = new Smb2LogoffResponse();
            Smb2LogoffResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2EchoResponse> HandleEcho(ulong sessionId, Smb2EchoRequest request)
        {
            Smb2EchoRequestValidator.Validate(request);

            if (!_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2EchoResponse());
            }

            Smb2EchoResponse response = new Smb2EchoResponse();
            Smb2EchoResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        private OpenCifsServerSessionSetupResult BeginSessionSetup(Smb2SessionSetupRequest request)
        {
            InitialSessionSetupToken? initialToken;
            NtStatus parseStatus;

            if (!_SessionSetupSupport.TryParseInitialSessionSetupToken(request.SecurityBuffer, out initialToken, out parseStatus) || initialToken == null)
            {
                return CreateSessionSetupResult(parseStatus, 0uL, new Smb2SessionSetupResponse());
            }

            if (initialToken.Flavor == SessionSetupFlavor.LegacyOpenCifs)
            {
                return BeginLegacySessionSetup(initialToken);
            }

            if (initialToken.Flavor == SessionSetupFlavor.SpnegoKerberos)
            {
                _WriteDiagnostic("Kerberos session setup was requested, but the Kerberos server path has not been implemented yet.");
                return CreateSessionSetupResult(NtStatus.NotSupported, 0uL, new Smb2SessionSetupResponse());
            }

            return BeginStandardSessionSetup(initialToken);
        }

        private OpenCifsServerSessionSetupResult CompleteSessionSetup(ulong sessionId, Smb2SessionSetupRequest request)
        {
            if (!_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord))
            {
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            if (sessionRecord.SessionSetupFlavor != SessionSetupFlavor.LegacyOpenCifs)
            {
                return CompleteStandardSessionSetup(sessionId, request, sessionRecord);
            }

            return CompleteLegacySessionSetup(sessionId, request, sessionRecord);
        }

        private OpenCifsServerSessionSetupResult BeginLegacySessionSetup(InitialSessionSetupToken initialToken)
        {
            OpenCifsNtlmNegotiateToken? negotiateToken = initialToken.LegacyNegotiateToken;
            SpnegoNegTokenInit? initToken = initialToken.SpnegoInitToken;

            if (initToken == null || negotiateToken == null)
            {
                return CreateSessionSetupResult(NtStatus.InvalidParameter, 0uL, new Smb2SessionSetupResponse());
            }

            ulong assignedSessionId = _AllocateSessionId();
            byte[] serverChallenge = new byte[8];
            RandomNumberGenerator.Fill(serverChallenge);

            ServerSessionRecord sessionRecord = new ServerSessionRecord
            {
                SessionSetupFlavor = SessionSetupFlavor.LegacyOpenCifs,
                SpnegoMechanismTypes = (string[])initToken.MechanismTypes.Clone(),
                UserName = negotiateToken.UserName,
                UserDomain = negotiateToken.UserDomain,
                ServerChallenge = serverChallenge,
                ExpectedServerName = _ServerName,
                ExpectedUserDomain = negotiateToken.UserDomain
            };
            sessionRecord.State.Bind(assignedSessionId);
            _Sessions[assignedSessionId] = sessionRecord;

            OpenCifsNtlmChallengeToken challengeToken = new OpenCifsNtlmChallengeToken
            {
                ServerChallenge = serverChallenge,
                ServerName = _ServerName,
                TargetDomain = negotiateToken.UserDomain
            };
            SpnegoNegTokenResp responseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(initToken, new string[1] { "1.3.6.1.4.1.311.2.2.10" }, challengeToken.ToByteArray());
            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = Smb2SessionFlags.None,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(responseToken)
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            return CreateSessionSetupResult(NtStatus.MoreProcessingRequired, assignedSessionId, response);
        }

        private OpenCifsServerSessionSetupResult BeginStandardSessionSetup(InitialSessionSetupToken initialToken)
        {
            NtlmNegotiateMessage? standardNegotiateMessage = initialToken.StandardNegotiateMessage;
            SpnegoNegTokenInit? spnegoInitToken = initialToken.SpnegoInitToken;

            if (standardNegotiateMessage == null)
            {
                return CreateSessionSetupResult(NtStatus.InvalidParameter, 0uL, new Smb2SessionSetupResponse());
            }

            if (initialToken.Flavor != SessionSetupFlavor.RawNtlm && spnegoInitToken == null)
            {
                return CreateSessionSetupResult(NtStatus.InvalidParameter, 0uL, new Smb2SessionSetupResponse());
            }

            SpnegoNegTokenInit standardSpnegoInitToken = spnegoInitToken!;

            ulong assignedSessionId = _AllocateSessionId();
            byte[] serverChallenge = new byte[8];
            RandomNumberGenerator.Fill(serverChallenge);
            string expectedServerName = _ServerName;
            string expectedUserDomain = _SessionSetupSupport.DetermineChallengeTargetDomain();
            NtlmChallengeMessage challengeMessage;

            try
            {
                challengeMessage = OpenCifsServerSessionSetupSupport.CreateStandardChallengeMessage(standardNegotiateMessage, serverChallenge, expectedServerName, expectedUserDomain);
            }
            catch (ProtocolEncodingException)
            {
                return CreateSessionSetupResult(NtStatus.InvalidParameter, 0uL, new Smb2SessionSetupResponse());
            }

            byte[] challengeBytes = challengeMessage.ToByteArray();
            ServerSessionRecord sessionRecord = new ServerSessionRecord
            {
                SessionSetupFlavor = initialToken.Flavor,
                SpnegoMechanismTypes = ((initialToken.SpnegoInitToken == null) ? null : ((string[])initialToken.SpnegoInitToken.MechanismTypes.Clone())),
                ServerChallenge = serverChallenge,
                ExpectedServerName = expectedServerName,
                ExpectedUserDomain = expectedUserDomain,
                NegotiateMessage = initialToken.StandardNegotiateMessageBytes,
                ChallengeMessage = challengeBytes
            };
            sessionRecord.State.Bind(assignedSessionId);
            _Sessions[assignedSessionId] = sessionRecord;

            byte[] responseSecurityBuffer = ((initialToken.Flavor == SessionSetupFlavor.RawNtlm)
                ? challengeBytes
                : SpnegoTokenCodec.EncodeNegTokenResp(SpnegoMechanismNegotiator.CreateNegotiationResponse(standardSpnegoInitToken, new string[1] { "1.3.6.1.4.1.311.2.2.10" }, challengeBytes)));
            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = Smb2SessionFlags.None,
                SecurityBuffer = responseSecurityBuffer
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            return CreateSessionSetupResult(NtStatus.MoreProcessingRequired, assignedSessionId, response);
        }

        private OpenCifsServerSessionSetupResult CompleteLegacySessionSetup(ulong sessionId, Smb2SessionSetupRequest request, ServerSessionRecord sessionRecord)
        {
            SpnegoNegTokenResp responseToken;

            try
            {
                responseToken = SpnegoTokenCodec.DecodeNegTokenResp(request.SecurityBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.InvalidParameter);
            }

            if (responseToken.ResponseToken == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.InvalidParameter);
            }

            OpenCifsNtlmAuthenticateToken authenticateToken;

            try
            {
                authenticateToken = OpenCifsNtlmAuthenticateToken.ReadFrom(responseToken.ResponseToken);
            }
            catch (ProtocolEncodingException)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.InvalidParameter);
            }

            if (!string.Equals(authenticateToken.UserName, sessionRecord.UserName, StringComparison.OrdinalIgnoreCase) || !string.Equals(authenticateToken.UserDomain, sessionRecord.UserDomain, StringComparison.OrdinalIgnoreCase))
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied);
            }

            OpenCifsServerAccount? account;

            if (!_SessionSetupSupport.TryGetAccount(authenticateToken.UserName, authenticateToken.UserDomain, out account) || account == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied);
            }

            if (!OpenCifsServerSessionSetupSupport.ValidateAuthenticateTokenTargetInfo(authenticateToken, sessionRecord.ExpectedServerName, sessionRecord.ExpectedUserDomain))
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied);
            }

            NtlmV2ChallengeResponseSet? verifiedResponseSet;

            if (!NtlmV2Authentication.TryVerifyChallengeResponseSet(account.Password, authenticateToken.UserName, authenticateToken.UserDomain, sessionRecord.ServerChallenge, authenticateToken.NtChallengeResponse, authenticateToken.LmChallengeResponse, out verifiedResponseSet) || verifiedResponseSet == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied);
            }

            NtStatus? legacyCallbackStatus = _InvokeAuthenticatedSessionCallback(sessionId, authenticateToken.UserName, authenticateToken.UserDomain, sessionRecord.SessionSetupFlavor);

            if (legacyCallbackStatus.HasValue && legacyCallbackStatus.Value != NtStatus.Success)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, legacyCallbackStatus.Value);
            }

            sessionRecord.State.Authenticate();
            sessionRecord.SessionBaseKey = verifiedResponseSet.SessionBaseKey;
            _SessionSecurityService.ApplyAuthenticatedSessionKeys(sessionRecord, verifiedResponseSet.SessionBaseKey);

            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = (sessionRecord.EncryptData ? Smb2SessionFlags.EncryptData : Smb2SessionFlags.None),
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptCompleted,
                    SupportedMechanism = "1.3.6.1.4.1.311.2.2.10"
                })
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            _WriteDiagnostic("Legacy NTLM session setup authenticated session " + sessionId + " for '" + authenticateToken.UserDomain + "\\" + authenticateToken.UserName + "'.");
            return CreateSessionSetupResult(NtStatus.Success, sessionId, response);
        }

        private OpenCifsServerSessionSetupResult CompleteStandardSessionSetup(ulong sessionId, Smb2SessionSetupRequest request, ServerSessionRecord sessionRecord)
        {
            byte[]? authenticateBytes;
            NtStatus extractionStatus;

            if (!OpenCifsServerSessionSetupSupport.TryExtractStandardAuthenticateToken(request.SecurityBuffer, sessionRecord.SessionSetupFlavor, out authenticateBytes, out extractionStatus) || authenticateBytes == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, extractionStatus, "Standard NTLM session setup failed during authenticate-token extraction with status " + extractionStatus.ToString() + ".");
            }

            NtlmAuthenticateMessage authenticateMessage;

            try
            {
                authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateBytes);
            }
            catch (ProtocolEncodingException)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.InvalidParameter, "Standard NTLM session setup failed because the authenticate message was malformed.");
            }

            string userName = authenticateMessage.UserName;
            string userDomain = authenticateMessage.DomainName;

            if (string.IsNullOrWhiteSpace(userName))
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because the authenticate message did not contain a user name.");
            }

            OpenCifsServerAccount? account;

            if (!_SessionSetupSupport.TryGetAccount(userName, userDomain, out account) || account == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because no registered account matched '" + userDomain + "\\" + userName + "'.");
            }

            if (!OpenCifsServerSessionSetupSupport.ValidateAuthenticateTokenTargetInfo(authenticateMessage.NtChallengeResponse, sessionRecord.ExpectedServerName, sessionRecord.ExpectedUserDomain))
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because the client target-info AV pairs did not match the issued challenge target.");
            }

            NtlmV2ChallengeResponseSet? verifiedResponseSet;

            if (!NtlmV2Authentication.TryVerifyChallengeResponseSet(account.Password, userName, userDomain, sessionRecord.ServerChallenge, authenticateMessage.NtChallengeResponse, authenticateMessage.LmChallengeResponse, out verifiedResponseSet) || verifiedResponseSet == null)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because the NTLMv2 challenge-response set did not verify for '" + userDomain + "\\" + userName + "'.");
            }

            byte[] sessionKey = verifiedResponseSet.SessionBaseKey;

            if ((authenticateMessage.Flags & NtlmNegotiateFlags.KeyExchange) != 0 && (authenticateMessage.Flags & (NtlmNegotiateFlags.Seal | NtlmNegotiateFlags.Sign)) != 0)
            {
                if (authenticateMessage.EncryptedRandomSessionKey.Length == 0)
                {
                    return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.InvalidParameter, "Standard NTLM session setup failed because key exchange was negotiated without an encrypted random session key.");
                }

                sessionKey = Rc4.Transform(verifiedResponseSet.SessionBaseKey, authenticateMessage.EncryptedRandomSessionKey);
            }

            if (authenticateMessage.MessageIntegrityCodeOffset != 0)
            {
                if (sessionRecord.NegotiateMessage == null || sessionRecord.ChallengeMessage == null || authenticateMessage.MessageIntegrityCode == null)
                {
                    return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because the MIC prerequisites were incomplete.");
                }

                byte[] authenticateBytesWithZeroMic = (byte[])authenticateBytes.Clone();
                Array.Clear(authenticateBytesWithZeroMic, authenticateMessage.MessageIntegrityCodeOffset, 16);

                if (!NtlmMessageIntegrityCode.Verify(sessionKey, sessionRecord.NegotiateMessage, sessionRecord.ChallengeMessage, authenticateBytesWithZeroMic, authenticateMessage.MessageIntegrityCode))
                {
                    return FailPendingSessionSetup(sessionId, sessionRecord, NtStatus.AccessDenied, "Standard NTLM session setup failed because the NTLM MIC did not verify for '" + userDomain + "\\" + userName + "'.");
                }
            }

            NtStatus? standardCallbackStatus = _InvokeAuthenticatedSessionCallback(sessionId, userName, userDomain, sessionRecord.SessionSetupFlavor);

            if (standardCallbackStatus.HasValue && standardCallbackStatus.Value != NtStatus.Success)
            {
                return FailPendingSessionSetup(sessionId, sessionRecord, standardCallbackStatus.Value);
            }

            sessionRecord.UserName = userName;
            sessionRecord.UserDomain = userDomain;
            sessionRecord.State.Authenticate();
            sessionRecord.SessionBaseKey = verifiedResponseSet.SessionBaseKey;
            _SessionSecurityService.ApplyAuthenticatedSessionKeys(sessionRecord, sessionKey);

            byte[]? mechanismListMic = null;

            if (sessionRecord.SessionSetupFlavor == SessionSetupFlavor.SpnegoNtlm && authenticateMessage.MessageIntegrityCodeOffset != 0 && sessionRecord.SpnegoMechanismTypes != null && sessionRecord.SpnegoMechanismTypes.Length != 0)
            {
                mechanismListMic = OpenCifsServerSessionSetupSupport.ComputeSpnegoMechanismListMic(sessionRecord.SpnegoMechanismTypes, authenticateMessage.Flags, sessionKey);
            }

            byte[] responseSecurityBuffer = ((sessionRecord.SessionSetupFlavor == SessionSetupFlavor.SpnegoNtlm) ? SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
            {
                NegotiationState = SpnegoNegState.AcceptCompleted,
                SupportedMechanism = "1.3.6.1.4.1.311.2.2.10",
                MechanismListMic = mechanismListMic
            }) : Array.Empty<byte>());
            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = (sessionRecord.EncryptData ? Smb2SessionFlags.EncryptData : Smb2SessionFlags.None),
                SecurityBuffer = responseSecurityBuffer
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            _WriteDiagnostic("Standard NTLM session setup authenticated session " + sessionId + " for '" + userDomain + "\\" + userName + "'.");
            return CreateSessionSetupResult(NtStatus.Success, sessionId, response);
        }

        private OpenCifsServerSessionSetupResult FailPendingSessionSetup(ulong sessionId, ServerSessionRecord sessionRecord, NtStatus status, string? diagnosticMessage = null)
        {
            if (!string.IsNullOrWhiteSpace(diagnosticMessage))
            {
                _WriteDiagnostic(diagnosticMessage);
            }

            _CleanupSessionRecord(sessionRecord);
            _Sessions.Remove(sessionId);
            return CreateSessionSetupResult(status, sessionId, new Smb2SessionSetupResponse());
        }

        private static OpenCifsServerOperationResult<TResponse> CreateOperationResult<TResponse>(NtStatus status, TResponse response) where TResponse : class
        {
            return new OpenCifsServerOperationResult<TResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerSessionSetupResult CreateSessionSetupResult(NtStatus status, ulong sessionId, Smb2SessionSetupResponse response)
        {
            return new OpenCifsServerSessionSetupResult
            {
                Status = status,
                SessionId = sessionId,
                Response = response
            };
        }
    }
}

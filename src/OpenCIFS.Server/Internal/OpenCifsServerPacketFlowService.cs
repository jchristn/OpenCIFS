namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsServerPacketFlowService
    {
        private readonly HashSet<ulong> _AvailableMessageIds = new HashSet<ulong>();
        private readonly CreditState _Credits = new CreditState();
        private readonly Dictionary<ulong, RequestState> _PendingRequests = new Dictionary<ulong, RequestState>();
        private readonly Dictionary<ulong, byte[]> _RetainedResponseEncryptionKeys = new Dictionary<ulong, byte[]>();
        private readonly Dictionary<ulong, byte[]> _RetainedResponseSigningKeys = new Dictionary<ulong, byte[]>();
        private readonly Func<Smb2SecurityMode> _GetCurrentClientSecurityMode;
        private readonly Func<SmbDialect?> _GetCurrentDialect;
        private readonly Func<SmbCipherAlgorithmId> _GetCurrentCipher;
        private readonly Func<Smb2SecurityMode> _GetCurrentServerSecurityMode;
        private readonly OpenCifsServerOptions _Options;
        private readonly IReadOnlyDictionary<ulong, ServerSessionRecord> _ReadOnlySessions;
        private readonly OpenCifsServerSessionSecurityService _SessionSecurityService;

        private ulong _NextMessageIdToGrant = 1uL;

        public OpenCifsServerPacketFlowService(
            IReadOnlyDictionary<ulong, ServerSessionRecord> sessions,
            OpenCifsServerOptions options,
            OpenCifsServerSessionSecurityService sessionSecurityService,
            Func<SmbDialect?> getCurrentDialect,
            Func<SmbCipherAlgorithmId> getCurrentCipher,
            Func<Smb2SecurityMode> getCurrentClientSecurityMode,
            Func<Smb2SecurityMode> getCurrentServerSecurityMode)
        {
            _ReadOnlySessions = sessions ?? throw new ArgumentNullException(nameof(sessions), "Sessions cannot be null.");
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _SessionSecurityService = sessionSecurityService ?? throw new ArgumentNullException(nameof(sessionSecurityService), "SessionSecurityService cannot be null.");
            _GetCurrentDialect = getCurrentDialect ?? throw new ArgumentNullException(nameof(getCurrentDialect), "GetCurrentDialect cannot be null.");
            _GetCurrentCipher = getCurrentCipher ?? throw new ArgumentNullException(nameof(getCurrentCipher), "GetCurrentCipher cannot be null.");
            _GetCurrentClientSecurityMode = getCurrentClientSecurityMode ?? throw new ArgumentNullException(nameof(getCurrentClientSecurityMode), "GetCurrentClientSecurityMode cannot be null.");
            _GetCurrentServerSecurityMode = getCurrentServerSecurityMode ?? throw new ArgumentNullException(nameof(getCurrentServerSecurityMode), "GetCurrentServerSecurityMode cannot be null.");
            _AvailableMessageIds.Add(0uL);
            _Credits.Grant(1);
        }

        public int AvailableCredits => _Credits.AvailableCredits;

        public Dictionary<ulong, RequestState> PendingRequests => _PendingRequests;

        public void ClearTransportState()
        {
            _PendingRequests.Clear();
            _RetainedResponseSigningKeys.Clear();
            _RetainedResponseEncryptionKeys.Clear();
        }

        public void ValidateAndAcceptRequestHeader(Smb2Header requestHeader, Smb2Command expectedCommand, ulong expectedSessionId = 0uL, uint expectedTreeId = 0u, Smb2HeaderFlags allowedRequestFlags = Smb2HeaderFlags.None)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            Smb2HeaderValidator.Validate(requestHeader);

            if (requestHeader.Command != expectedCommand)
            {
                throw new ProtocolValidationException("The SMB2 request header command does not match the expected request body.", nameof(requestHeader));
            }

            if ((requestHeader.Flags & ~(allowedRequestFlags | Smb2HeaderFlags.Signed)) != Smb2HeaderFlags.None)
            {
                throw new ProtocolValidationException("The SMB2 request header contains flags that are not supported in the current SMB 2.0.2 slice.", nameof(requestHeader));
            }

            if (requestHeader.SessionId != expectedSessionId)
            {
                throw new ProtocolValidationException("The SMB2 request header session identifier does not match the expected session.", nameof(requestHeader));
            }

            if (requestHeader.TreeId != expectedTreeId)
            {
                throw new ProtocolValidationException("The SMB2 request header tree identifier does not match the expected tree.", nameof(requestHeader));
            }

            int creditsToConsume = DetermineCreditsToConsume(requestHeader);
            ReserveMessageIdRange(requestHeader.MessageId, creditsToConsume, nameof(requestHeader));
            _Credits.Consume(creditsToConsume);

            RequestState requestState = new RequestState();
            requestState.Bind(requestHeader);
            _PendingRequests[requestHeader.MessageId] = requestState;
        }

        public Smb2Header CreateResponseHeader(Smb2Header requestHeader, NtStatus status, ulong sessionId = 0uL, uint treeId = 0u, Smb2HeaderFlags additionalFlags = Smb2HeaderFlags.None)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            RequestState requestState = GetPendingRequest(requestHeader.MessageId);

            if (requestState.Command != requestHeader.Command)
            {
                throw new ProtocolValidationException("The accepted SMB2 request does not match the response command.", nameof(requestHeader));
            }

            if (requestState.AsyncId != 0)
            {
                ulong asyncId = requestState.AsyncId;
                requestState.Complete();
                requestState.Dispose();
                _PendingRequests.Remove(requestHeader.MessageId);

                Smb2Header asyncResponseHeader = new Smb2Header
                {
                    CreditCharge = 0,
                    Status = status,
                    Command = requestHeader.Command,
                    CreditRequest = 0,
                    Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand | (requestHeader.Flags & Smb2HeaderFlags.Signed) | additionalFlags,
                    NextCommand = 0,
                    MessageId = requestHeader.MessageId,
                    AsyncId = asyncId,
                    SessionId = sessionId != 0L ? sessionId : requestHeader.SessionId,
                    Signature = new byte[16]
                };

                Smb2HeaderValidator.Validate(asyncResponseHeader);
                return asyncResponseHeader;
            }

            ushort creditsGranted = DetermineCreditsToGrant(requestHeader.CreditRequest);
            GrantCredits(creditsGranted);
            requestState.Complete();
            requestState.Dispose();
            _PendingRequests.Remove(requestHeader.MessageId);

            Smb2Header responseHeader = new Smb2Header
            {
                CreditCharge = 0,
                Status = status,
                Command = requestHeader.Command,
                CreditRequest = creditsGranted,
                Flags = Smb2HeaderFlags.ServerToRedir | (requestHeader.Flags & Smb2HeaderFlags.Signed) | additionalFlags,
                NextCommand = 0,
                MessageId = requestHeader.MessageId,
                ProcessId = requestHeader.ProcessId,
                TreeId = treeId != 0 ? treeId : requestHeader.TreeId,
                SessionId = sessionId != 0L ? sessionId : requestHeader.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(responseHeader);
            return responseHeader;
        }

        public byte[] FinalizeResponsePacket(Smb2CompoundPacket responsePacket)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            byte[] packetBytes = responsePacket.ToByteArray();

            if (TryGetEncryptedResponsePacketSessionId(responsePacket, out ulong encryptedSessionId) &&
                TryGetResponseEncryptionKey(encryptedSessionId, out byte[]? encryptionKey, out bool retainedEncryptionKey) &&
                encryptionKey != null)
            {
                byte[] encryptedPacket = Smb3MessageTransform.EncryptPacket(packetBytes, encryptedSessionId, encryptionKey, _GetCurrentCipher());
                _RetainedResponseSigningKeys.Remove(encryptedSessionId);

                if (retainedEncryptionKey)
                {
                    _RetainedResponseEncryptionKeys.Remove(encryptedSessionId);
                }

                return encryptedPacket;
            }

            IMessageSigner signer = _SessionSecurityService.CreateNegotiatedMessageSigner();
            HashSet<ulong>? consumedRetainedSigningKeys = null;
            int offset = 0;

            for (int index = 0; index < responsePacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[index];
                int entryLength = responseEntry.Header.NextCommand == 0 ? packetBytes.Length - offset : checked((int)responseEntry.Header.NextCommand);

                if ((responseEntry.Header.Flags & Smb2HeaderFlags.Signed) != Smb2HeaderFlags.None &&
                    TryGetResponseSigningKey(responseEntry.Header.SessionId, out byte[]? signingKey, out bool retainedSigningKey) &&
                    signingKey != null)
                {
                    Array.Clear(packetBytes, offset + 48, 16);
                    ReadOnlySpan<byte> serverSignNonce = signer.RequiresNonce
                        ? Smb2SigningNonce.BuildSmb311GmacNonce(responseEntry.Header.MessageId, isServerToClient: true)
                        : ReadOnlySpan<byte>.Empty;
                    byte[] signature = signer.Sign(packetBytes.AsSpan(offset, entryLength), signingKey, serverSignNonce);
                    Buffer.BlockCopy(signature, 0, packetBytes, offset + 48, signature.Length);

                    if (retainedSigningKey)
                    {
                        consumedRetainedSigningKeys ??= new HashSet<ulong>();
                        consumedRetainedSigningKeys.Add(responseEntry.Header.SessionId);
                    }
                }

                offset += entryLength;
            }

            if (consumedRetainedSigningKeys != null)
            {
                foreach (ulong sessionId in consumedRetainedSigningKeys)
                {
                    _RetainedResponseSigningKeys.Remove(sessionId);
                }
            }

            return packetBytes;
        }

        public void ValidateRequestPacket(Smb2CompoundPacket requestPacket, ReadOnlyMemory<byte> packetBytes, bool wasEncrypted = false)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            IMessageSigner signer = _SessionSecurityService.CreateNegotiatedMessageSigner();
            int offset = 0;

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[index];
                Smb2Header requestHeader = requestEntry.Header;
                int entryLength = requestHeader.NextCommand == 0 ? packetBytes.Length - offset : checked((int)requestHeader.NextCommand);
                byte[]? signingKey = null;
                bool requestMustBeSigned = !wasEncrypted && ShouldRequireSignedRequest(requestHeader, out signingKey);

                if (requestHeader.Command == Smb2Command.Negotiate && (requestHeader.Flags & Smb2HeaderFlags.Signed) != Smb2HeaderFlags.None)
                {
                    throw new ProtocolValidationException("The SMB2 negotiate request must not set the Signed flag.", nameof(requestPacket));
                }

                if ((requestHeader.Flags & Smb2HeaderFlags.Signed) == 0)
                {
                    if (requestMustBeSigned)
                    {
                        throw new ProtocolValidationException("The SMB2 request omitted the required Signed flag.", nameof(requestPacket));
                    }

                    offset += entryLength;
                    continue;
                }

                if (wasEncrypted)
                {
                    offset += entryLength;
                    continue;
                }

                if (signingKey == null || signingKey.Length == 0)
                {
                    throw new ProtocolValidationException("The server does not have a signing key for the signed SMB2 request.", nameof(requestPacket));
                }

                byte[] expectedMessage = packetBytes.Slice(offset, entryLength).ToArray();
                Array.Clear(expectedMessage, 48, 16);
                ReadOnlySpan<byte> serverVerifyNonce = signer.RequiresNonce
                    ? Smb2SigningNonce.BuildSmb311GmacNonce(requestHeader.MessageId, isServerToClient: false)
                    : ReadOnlySpan<byte>.Empty;

                if (!signer.Verify(expectedMessage, signingKey, serverVerifyNonce, requestHeader.Signature))
                {
                    throw new ProtocolValidationException("The SMB2 request signature did not verify.", nameof(requestPacket));
                }

                offset += entryLength;
            }
        }

        public byte[] UnwrapRequestPacket(ReadOnlyMemory<byte> requestPacketBytes, out bool wasEncrypted)
        {
            if (!Smb2TransformHeader.LooksLikeTransformHeader(requestPacketBytes.Span))
            {
                wasEncrypted = false;
                return requestPacketBytes.ToArray();
            }

            Smb2TransformHeader header = Smb2TransformHeader.ReadFrom(requestPacketBytes);

            if (!TryGetSessionDecryptionKey(header.SessionId, out byte[]? decryptionKey) || decryptionKey == null)
            {
                throw new ProtocolValidationException("The server does not have an SMB3 decryption key for the encrypted request session.", nameof(requestPacketBytes));
            }

            wasEncrypted = true;
            return Smb3MessageTransform.DecryptPacket(requestPacketBytes, decryptionKey, header.SessionId, _GetCurrentCipher());
        }

        public OpenCifsServerCancelResult HandleCancel(Smb2Header requestHeader, Smb2CancelRequest request, Action<ulong> removePendingChangeNotifySubscription)
        {
            ValidateCancelRequestHeader(requestHeader);
            Smb2CancelRequestValidator.Validate(request);

            if (removePendingChangeNotifySubscription == null)
            {
                throw new ArgumentNullException(nameof(removePendingChangeNotifySubscription), "RemovePendingChangeNotifySubscription cannot be null.");
            }

            OpenCifsServerCancelResult result = new OpenCifsServerCancelResult();

            if ((requestHeader.Flags & Smb2HeaderFlags.AsyncCommand) != Smb2HeaderFlags.None)
            {
                if (!TryGetPendingRequestByAsyncId(requestHeader.AsyncId, out RequestState? asyncRequestState) ||
                    asyncRequestState == null ||
                    asyncRequestState.Header == null ||
                    asyncRequestState.Command == Smb2Command.Cancel)
                {
                    return result;
                }

                Smb2Header asyncTargetHeader = asyncRequestState.Header;

                if (requestHeader.SessionId != asyncTargetHeader.SessionId)
                {
                    return result;
                }

                asyncRequestState.Cancel();
                removePendingChangeNotifySubscription(asyncTargetHeader.MessageId);

                Smb2ErrorResponse cancelledErrorResponse = new Smb2ErrorResponse();
                Smb2ErrorResponseValidator.Validate(cancelledErrorResponse);
                result.TargetResponseHeader = CreateResponseHeader(asyncTargetHeader, NtStatus.Cancelled, asyncTargetHeader.SessionId, asyncTargetHeader.TreeId);
                result.TargetResponsePayload = cancelledErrorResponse.ToByteArray();
                result.WasCancelled = true;
                return result;
            }

            if (!_PendingRequests.TryGetValue(requestHeader.MessageId, out RequestState? requestState) ||
                requestState.Header == null ||
                requestState.Command == Smb2Command.Cancel)
            {
                return result;
            }

            Smb2Header targetHeader = requestState.Header;

            if (requestHeader.SessionId != targetHeader.SessionId)
            {
                return result;
            }

            if (!OpenCifsServerDefaultResponsePayloadFactory.TryCreateDefaultResponsePayload(targetHeader.Command, out byte[]? payload) || payload == null)
            {
                return result;
            }

            requestState.Cancel();
            result.TargetResponseHeader = CreateResponseHeader(targetHeader, NtStatus.Cancelled, targetHeader.SessionId, targetHeader.TreeId);
            result.TargetResponsePayload = payload;
            result.WasCancelled = true;
            return result;
        }

        public ushort DetermineCreditsToGrant(ushort requestedCredits)
        {
            int remainingCapacity = _Options.MaximumCredits - _Credits.AvailableCredits;
            int boundedGrant = Math.Clamp(requestedCredits, 1, Math.Max(1, remainingCapacity));
            return (ushort)boundedGrant;
        }

        public void ValidateReadWriteCreditCharge(Smb2Header requestHeader, uint length, string argumentName)
        {
            ushort expectedCredits = Smb2CreditChargeHelper.GetRequiredReadWriteCredits(_GetCurrentDialect(), length);

            if (requestHeader.CreditCharge == 0)
            {
                if (expectedCredits > 1)
                {
                    throw new ProtocolValidationException("The SMB2 request CreditCharge is too small for the bounded large-I/O length.", argumentName);
                }
            }
            else if (requestHeader.CreditCharge < expectedCredits)
            {
                throw new ProtocolValidationException("The SMB2 request CreditCharge is too small for the bounded large-I/O length.", argumentName);
            }
        }

        public void GrantCredits(ushort creditCount)
        {
            _Credits.Grant(creditCount);

            for (ushort index = 0; index < creditCount; index++)
            {
                _AvailableMessageIds.Add(_NextMessageIdToGrant);
                _NextMessageIdToGrant++;
            }
        }

        public RequestState GetPendingRequest(ulong messageId)
        {
            if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState))
            {
                throw new ProtocolValidationException("The SMB2 response header does not match any accepted request on this host.", nameof(messageId));
            }

            return requestState;
        }

        public void RetainResponseSigningKey(ulong sessionId, ServerSessionRecord sessionRecord)
        {
            if (sessionRecord.SessionKey == null || sessionRecord.SessionKey.Length == 0)
            {
                _RetainedResponseSigningKeys.Remove(sessionId);
                return;
            }

            _RetainedResponseSigningKeys[sessionId] = (byte[])sessionRecord.SessionKey.Clone();
        }

        public void RetainResponseEncryptionKey(ulong sessionId, ServerSessionRecord sessionRecord)
        {
            if (sessionRecord.EncryptionKey == null || sessionRecord.EncryptionKey.Length == 0 || !sessionRecord.EncryptData)
            {
                _RetainedResponseEncryptionKeys.Remove(sessionId);
                return;
            }

            _RetainedResponseEncryptionKeys[sessionId] = (byte[])sessionRecord.EncryptionKey.Clone();
        }

        public Smb2Header CreateOplockBreakNotificationHeader(ServerOpenRecord openRecord)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            Smb2HeaderFlags flags = Smb2HeaderFlags.ServerToRedir;

            if (!IsSessionEncryptionActive(openRecord.SessionId) &&
                TryGetSessionSigningKey(openRecord.SessionId, out byte[]? _) &&
                (_Options.RequireSigning || IsSessionSigningRequired()))
            {
                flags |= Smb2HeaderFlags.Signed;
            }

            Smb2Header header = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = Smb2Command.OplockBreak,
                CreditRequest = 0,
                Flags = flags,
                NextCommand = 0,
                MessageId = ulong.MaxValue,
                TreeId = openRecord.TreeId,
                SessionId = openRecord.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(header);
            return header;
        }

        private int DetermineCreditsToConsume(Smb2Header requestHeader)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (requestHeader.Command == Smb2Command.Cancel)
            {
                return 0;
            }

            if (requestHeader.CreditCharge == 0)
            {
                return 1;
            }

            if (requestHeader.Command != Smb2Command.Read && requestHeader.Command != Smb2Command.Write)
            {
                if (requestHeader.CreditCharge > 1)
                {
                    throw new ProtocolValidationException("Only bounded SMB 2.1 read and write requests may consume multiple SMB2 credits.", nameof(requestHeader));
                }

                return 1;
            }

            SmbDialect? currentDialect = _GetCurrentDialect();

            if (!currentDialect.HasValue || currentDialect.Value < SmbDialect.Smb21)
            {
                if (requestHeader.CreditCharge > 1)
                {
                    throw new ProtocolValidationException("Multi-credit SMB2 read and write requests require the negotiated SMB 2.1 dialect.", nameof(requestHeader));
                }

                return 1;
            }

            return requestHeader.CreditCharge;
        }

        private void ReserveMessageIdRange(ulong startingMessageId, int creditsToConsume, string argumentName)
        {
            for (int index = 0; index < creditsToConsume; index++)
            {
                ulong messageId = startingMessageId + (ulong)index;

                if (!_AvailableMessageIds.Remove(messageId))
                {
                    throw new ProtocolValidationException("The SMB2 request message identifier is outside the current server credit window.", argumentName);
                }
            }
        }

        private bool TryGetPendingRequestByAsyncId(ulong asyncId, out RequestState? requestState)
        {
            foreach (RequestState candidate in _PendingRequests.Values)
            {
                if (candidate.AsyncId == asyncId)
                {
                    requestState = candidate;
                    return true;
                }
            }

            requestState = null;
            return false;
        }

        private bool TryGetSessionSigningKey(ulong sessionId, out byte[]? signingKey)
        {
            if (_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) &&
                sessionRecord != null &&
                sessionRecord.State.IsAuthenticated &&
                sessionRecord.SessionKey != null &&
                sessionRecord.SessionKey.Length != 0)
            {
                signingKey = sessionRecord.SessionKey;
                return true;
            }

            signingKey = null;
            return false;
        }

        private bool TryGetSessionEncryptionKey(ulong sessionId, out byte[]? encryptionKey)
        {
            if (_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) &&
                sessionRecord != null &&
                sessionRecord.State.IsAuthenticated &&
                sessionRecord.EncryptData &&
                sessionRecord.EncryptionKey != null &&
                sessionRecord.EncryptionKey.Length != 0)
            {
                encryptionKey = sessionRecord.EncryptionKey;
                return true;
            }

            encryptionKey = null;
            return false;
        }

        private bool TryGetSessionDecryptionKey(ulong sessionId, out byte[]? decryptionKey)
        {
            if (_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) &&
                sessionRecord != null &&
                sessionRecord.State.IsAuthenticated &&
                sessionRecord.EncryptData &&
                sessionRecord.DecryptionKey != null &&
                sessionRecord.DecryptionKey.Length != 0)
            {
                decryptionKey = sessionRecord.DecryptionKey;
                return true;
            }

            decryptionKey = null;
            return false;
        }

        private bool IsSessionEncryptionActive(ulong sessionId)
        {
            return sessionId != 0L &&
                _ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) &&
                sessionRecord != null &&
                sessionRecord.State.IsAuthenticated &&
                sessionRecord.EncryptData;
        }

        private bool TryGetResponseSigningKey(ulong sessionId, out byte[]? signingKey, out bool retainedSigningKey)
        {
            if (TryGetSessionSigningKey(sessionId, out signingKey))
            {
                retainedSigningKey = false;
                return true;
            }

            if (_RetainedResponseSigningKeys.TryGetValue(sessionId, out byte[]? retainedKey) &&
                retainedKey != null &&
                retainedKey.Length != 0)
            {
                signingKey = retainedKey;
                retainedSigningKey = true;
                return true;
            }

            signingKey = null;
            retainedSigningKey = false;
            return false;
        }

        private bool TryGetResponseEncryptionKey(ulong sessionId, out byte[]? encryptionKey, out bool retainedEncryptionKey)
        {
            if (TryGetSessionEncryptionKey(sessionId, out encryptionKey))
            {
                retainedEncryptionKey = false;
                return true;
            }

            if (_RetainedResponseEncryptionKeys.TryGetValue(sessionId, out byte[]? retainedKey) &&
                retainedKey != null &&
                retainedKey.Length != 0)
            {
                encryptionKey = retainedKey;
                retainedEncryptionKey = true;
                return true;
            }

            encryptionKey = null;
            retainedEncryptionKey = false;
            return false;
        }

        private bool TryGetEncryptedResponsePacketSessionId(Smb2CompoundPacket responsePacket, out ulong sessionId)
        {
            sessionId = 0uL;

            if (responsePacket.Entries.Count == 0)
            {
                return false;
            }

            ulong candidateSessionId = responsePacket.Entries[0].Header.SessionId;

            if (candidateSessionId == 0L ||
                (!IsSessionEncryptionActive(candidateSessionId) && !_RetainedResponseEncryptionKeys.ContainsKey(candidateSessionId)))
            {
                return false;
            }

            for (int index = 0; index < responsePacket.Entries.Count; index++)
            {
                Smb2Header header = responsePacket.Entries[index].Header;

                if (header.SessionId != candidateSessionId)
                {
                    throw new OpenCifsServerStateException("The bounded SMB3 encrypted response path does not support compounded packets that mix SMB2 session identifiers.");
                }

                if (header.Command == Smb2Command.Negotiate || header.Command == Smb2Command.SessionSetup)
                {
                    return false;
                }
            }

            sessionId = candidateSessionId;
            return true;
        }

        private bool ShouldRequireSignedRequest(Smb2Header requestHeader, out byte[]? signingKey)
        {
            signingKey = null;

            if (requestHeader.SessionId == 0L || requestHeader.Command == Smb2Command.Negotiate || requestHeader.Command == Smb2Command.SessionSetup)
            {
                return false;
            }

            if (!TryGetSessionSigningKey(requestHeader.SessionId, out signingKey))
            {
                return false;
            }

            if (IsSessionEncryptionActive(requestHeader.SessionId))
            {
                return false;
            }

            return _Options.RequireSigning || IsSessionSigningRequired();
        }

        private bool IsSessionSigningRequired()
        {
            return (_GetCurrentServerSecurityMode() & Smb2SecurityMode.SigningRequired) != Smb2SecurityMode.None ||
                (_GetCurrentClientSecurityMode() & Smb2SecurityMode.SigningRequired) != 0;
        }

        private static void ValidateCancelRequestHeader(Smb2Header requestHeader)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            Smb2HeaderValidator.Validate(requestHeader);

            if (requestHeader.Command != Smb2Command.Cancel)
            {
                throw new ProtocolValidationException("The SMB2 request header command does not identify a cancel request.", nameof(requestHeader));
            }

            if (requestHeader.CreditRequest > 1)
            {
                throw new ProtocolValidationException("The bounded SMB2 cancel request surface only accepts CreditRequest values of 0 or 1.", nameof(requestHeader));
            }

            if (requestHeader.NextCommand != 0)
            {
                throw new ProtocolValidationException("The bounded SMB2 cancel request surface does not support compounding.", nameof(requestHeader));
            }

            if (((uint)requestHeader.Flags & 0xFFFFFFF5u) != 0)
            {
                throw new ProtocolValidationException("The bounded SMB2 cancel request surface only supports signed or unsigned synchronous or async cancel headers.", nameof(requestHeader));
            }

            if ((requestHeader.Flags & Smb2HeaderFlags.AsyncCommand) != Smb2HeaderFlags.None && requestHeader.AsyncId == 0)
            {
                throw new ProtocolValidationException("Asynchronous SMB2 cancel headers must carry a non-zero AsyncId.", nameof(requestHeader));
            }
        }
    }
}

namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsClientSessionPacketService
    {
        private const int Smb2HeaderSignatureOffset = 48;
        private const int Smb2HeaderSignatureLength = 16;

        public OpenCifsClientSessionPacketService(
            OpenCifsClientSessionPacketState packetState,
            Func<SessionState> getSessionState,
            Func<ulong?> getSessionId,
            Func<SmbDialect?> getNegotiatedDialect,
            Func<bool> getIsAuthenticated,
            Func<bool> getIsSigningRequired,
            Func<Smb2GlobalCapabilities> getNegotiatedServerCapabilities,
            Func<SmbCipherAlgorithmId> getNegotiatedCipher,
            Func<byte[]?> getSessionSigningKey,
            Func<byte[]?> getSessionEncryptionKey,
            Func<byte[]?> getSessionDecryptionKey,
            Func<bool> getIsSessionEncryptionRequired)
        {
            _PacketState = packetState ?? throw new ArgumentNullException(nameof(packetState), "PacketState cannot be null.");
            _GetSessionState = getSessionState ?? throw new ArgumentNullException(nameof(getSessionState), "GetSessionState cannot be null.");
            _GetSessionId = getSessionId ?? throw new ArgumentNullException(nameof(getSessionId), "GetSessionId cannot be null.");
            _GetNegotiatedDialect = getNegotiatedDialect ?? throw new ArgumentNullException(nameof(getNegotiatedDialect), "GetNegotiatedDialect cannot be null.");
            _GetIsAuthenticated = getIsAuthenticated ?? throw new ArgumentNullException(nameof(getIsAuthenticated), "GetIsAuthenticated cannot be null.");
            _GetIsSigningRequired = getIsSigningRequired ?? throw new ArgumentNullException(nameof(getIsSigningRequired), "GetIsSigningRequired cannot be null.");
            _GetNegotiatedServerCapabilities = getNegotiatedServerCapabilities ?? throw new ArgumentNullException(nameof(getNegotiatedServerCapabilities), "GetNegotiatedServerCapabilities cannot be null.");
            _GetNegotiatedCipher = getNegotiatedCipher ?? throw new ArgumentNullException(nameof(getNegotiatedCipher), "GetNegotiatedCipher cannot be null.");
            _GetSessionSigningKey = getSessionSigningKey ?? throw new ArgumentNullException(nameof(getSessionSigningKey), "GetSessionSigningKey cannot be null.");
            _GetSessionEncryptionKey = getSessionEncryptionKey ?? throw new ArgumentNullException(nameof(getSessionEncryptionKey), "GetSessionEncryptionKey cannot be null.");
            _GetSessionDecryptionKey = getSessionDecryptionKey ?? throw new ArgumentNullException(nameof(getSessionDecryptionKey), "GetSessionDecryptionKey cannot be null.");
            _GetIsSessionEncryptionRequired = getIsSessionEncryptionRequired ?? throw new ArgumentNullException(nameof(getIsSessionEncryptionRequired), "GetIsSessionEncryptionRequired cannot be null.");
        }

        public Smb2Header CreateRequestHeader(Smb2Command command, uint treeId = 0, ushort creditRequest = 1, ulong? sessionId = null, ushort creditCharge = 0)
        {
            if (!Enum.IsDefined(typeof(Smb2Command), command))
            {
                throw new ArgumentOutOfRangeException(nameof(command), "The SMB2 command is not recognized.");
            }

            if (creditRequest == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(creditRequest), "CreditRequest must be greater than zero for SMB 2.0.2 requests.");
            }

            ulong effectiveSessionId = sessionId ?? (command == Smb2Command.Negotiate ? 0UL : _GetSessionId() ?? 0UL);

            if (treeId != 0 && effectiveSessionId == 0)
            {
                throw new OpenCifsClientStateException("A non-zero tree identifier requires a session-scoped SMB2 request.");
            }

            ValidateCompatibleCreditCharge(command, creditCharge);
            int creditsToConsume = DetermineCreditsToConsume(command, creditCharge);

            if (_PacketState.AvailableMessageIds.Count < creditsToConsume)
            {
                throw new OpenCifsClientStateException("The local SMB2 message identifier window does not have enough contiguous sequence numbers for the outbound request.");
            }

            _PacketState.ConnectionState.Credits.Consume(creditsToConsume);
            ulong messageId = DequeueMessageIdRange(creditsToConsume);
            Smb2Header header = new Smb2Header
            {
                CreditCharge = creditCharge,
                Status = NtStatus.Success,
                Command = command,
                CreditRequest = creditRequest,
                Flags = ShouldSignCommand(command, effectiveSessionId)
                    ? Smb2HeaderFlags.Signed
                    : Smb2HeaderFlags.None,
                NextCommand = 0,
                MessageId = messageId,
                ProcessId = 0,
                TreeId = treeId,
                SessionId = effectiveSessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(header);
            RequestState requestState = new RequestState();
            requestState.Bind(header);
            _PacketState.PendingRequests[messageId] = requestState;
            return header;
        }

        public Smb2Header CreateCancelRequestHeader(ulong messageId)
        {
            if (!_PacketState.PendingRequests.TryGetValue(messageId, out RequestState? requestState) || requestState.Header == null)
            {
                throw new OpenCifsClientStateException("The specified SMB2 message identifier is not currently pending on this client session.");
            }

            Smb2Header pendingHeader = requestState.Header;
            Smb2Header header = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = Smb2Command.Cancel,
                CreditRequest = 0,
                Flags =
                    (requestState.AsyncId != 0 ? Smb2HeaderFlags.AsyncCommand : Smb2HeaderFlags.None) |
                    (ShouldSignCommand(Smb2Command.Cancel, pendingHeader.SessionId) ? Smb2HeaderFlags.Signed : Smb2HeaderFlags.None),
                NextCommand = 0,
                MessageId = pendingHeader.MessageId,
                ProcessId = requestState.AsyncId == 0 ? pendingHeader.ProcessId : 0,
                TreeId = requestState.AsyncId == 0 ? pendingHeader.TreeId : 0,
                AsyncId = requestState.AsyncId,
                SessionId = pendingHeader.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(header);
            return header;
        }

        public Smb2Header CreateRelatedRequestHeader(Smb2Command command, uint treeId = 0, ushort creditRequest = 1, ulong? sessionId = null)
        {
            Smb2Header header = CreateRequestHeader(command, treeId, creditRequest, sessionId);
            header.Flags |= Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(header);
            return header;
        }

        public void ApplyResponseHeader(Smb2Header responseHeader)
        {
            ApplyResponseHeader(responseHeader, allowZeroSynchronousCreditGrant: false);
        }

        private void ApplyResponseHeader(Smb2Header responseHeader, bool allowZeroSynchronousCreditGrant)
        {
            if (responseHeader == null)
            {
                throw new ArgumentNullException(nameof(responseHeader), "ResponseHeader cannot be null.");
            }

            Smb2HeaderValidator.Validate(responseHeader);

            if ((responseHeader.Flags & Smb2HeaderFlags.ServerToRedir) == 0)
            {
                throw new OpenCifsClientProtocolException("SMB2 response headers must set the ServerToRedir flag.", nameof(responseHeader));
            }

            Smb2HeaderFlags unsupportedFlags = responseHeader.Flags & ~(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.Signed | Smb2HeaderFlags.RelatedOperations | Smb2HeaderFlags.AsyncCommand);

            if (unsupportedFlags != Smb2HeaderFlags.None)
            {
                throw new OpenCifsClientProtocolException("The response header contains SMB2 flags that are not supported in the current SMB 2.0.2 slice.", nameof(responseHeader));
            }

            RequestState requestState = GetPendingRequest(responseHeader.MessageId);

            if (requestState.Command != responseHeader.Command)
            {
                throw new OpenCifsClientProtocolException("The SMB2 response command does not match the pending request.", nameof(responseHeader));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                if ((responseHeader.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
                {
                    throw new OpenCifsClientProtocolException("Async SMB2 responses are not supported inside related compounded chains in the current slice.", nameof(responseHeader));
                }

                if (responseHeader.Status == NtStatus.Pending)
                {
                    if (responseHeader.CreditRequest == 0)
                    {
                        throw new OpenCifsClientProtocolException("Interim async SMB2 responses must grant at least one credit.", nameof(responseHeader));
                    }

                    GrantCredits(responseHeader.CreditRequest);
                    requestState.MarkAsync(responseHeader.AsyncId);
                    return;
                }

                if (responseHeader.CreditRequest != 0)
                {
                    throw new OpenCifsClientProtocolException("Final async SMB2 responses must not grant additional credits in the current slice.", nameof(responseHeader));
                }

                if (requestState.AsyncId == 0 || requestState.AsyncId != responseHeader.AsyncId)
                {
                    throw new OpenCifsClientProtocolException("The async SMB2 response does not match the pending request AsyncId.", nameof(responseHeader));
                }
            }
            else
            {
                if (responseHeader.CreditRequest == 0)
                {
                    if (allowZeroSynchronousCreditGrant)
                    {
                        requestState.Complete();
                        requestState.Dispose();
                        _PacketState.PendingRequests.Remove(responseHeader.MessageId);
                        return;
                    }

                    throw new OpenCifsClientProtocolException("SMB 2.0.2 synchronous response headers must grant at least one credit.", nameof(responseHeader));
                }

                GrantCredits(responseHeader.CreditRequest);
            }

            requestState.Complete();
            requestState.Dispose();
            _PacketState.PendingRequests.Remove(responseHeader.MessageId);
        }

        public void ApplyCompoundResponsePacket(Smb2CompoundPacket responsePacket)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            IReadOnlyList<Smb2CompoundPacketEntry> entries = responsePacket.Entries;

            for (int index = 0; index < entries.Count; index++)
            {
                ApplyResponseHeader(entries[index].Header, allowZeroSynchronousCreditGrant: index < entries.Count - 1);
            }
        }

        public byte[] FinalizeRequestPacket(Smb2CompoundPacket requestPacket)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            byte[] packetBytes = requestPacket.ToByteArray();
            IMessageSigner signer = OpenCifsClientSessionProtocolSupport.CreateNegotiatedMessageSigner(_GetNegotiatedDialect());
            int offset = 0;

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[index];
                int entryLength = requestEntry.Header.NextCommand == 0
                    ? packetBytes.Length - offset
                    : checked((int)requestEntry.Header.NextCommand);

                if ((requestEntry.Header.Flags & Smb2HeaderFlags.Signed) != 0)
                {
                    byte[] signingKey = GetSessionSigningKey(requestEntry.Header.SessionId);
                    Array.Clear(packetBytes, offset + Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);
                    ReadOnlySpan<byte> signingNonce = signer.RequiresNonce
                        ? Smb2SigningNonce.BuildSmb311GmacNonce(requestEntry.Header.MessageId, isServerToClient: false)
                        : ReadOnlySpan<byte>.Empty;
                    byte[] signature = signer.Sign(packetBytes.AsSpan(offset, entryLength), signingKey, signingNonce);
                    Buffer.BlockCopy(signature, 0, packetBytes, offset + Smb2HeaderSignatureOffset, signature.Length);
                }

                offset += entryLength;
            }

            if (TryGetEncryptedPacketSessionId(requestPacket, out ulong encryptedSessionId))
            {
                return Smb3MessageTransform.EncryptPacket(packetBytes, encryptedSessionId, GetSessionEncryptionKey(encryptedSessionId), _GetNegotiatedCipher());
            }

            return packetBytes;
        }

        public byte[] UnwrapResponsePacket(ReadOnlyMemory<byte> packetBytes)
        {
            if (!Smb2TransformHeader.LooksLikeTransformHeader(packetBytes.Span))
            {
                return packetBytes.ToArray();
            }

            Smb2TransformHeader header = Smb2TransformHeader.ReadFrom(packetBytes);
            return Smb3MessageTransform.DecryptPacket(packetBytes, GetSessionDecryptionKey(header.SessionId), expectedSessionId: _GetSessionId(), cipher: _GetNegotiatedCipher());
        }

        public void ValidateResponsePacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            IMessageSigner signer = OpenCifsClientSessionProtocolSupport.CreateNegotiatedMessageSigner(_GetNegotiatedDialect());
            int offset = 0;

            for (int index = 0; index < responsePacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[index];
                Smb2Header responseHeader = responseEntry.Header;
                RequestState requestState = GetPendingRequest(responseHeader.MessageId);
                int entryLength = responseHeader.NextCommand == 0
                    ? packetBytes.Length - offset
                    : checked((int)responseHeader.NextCommand);
                bool responseShouldBeSigned = ShouldRequireSignedResponse(requestState, responseHeader);

                if ((responseHeader.Flags & Smb2HeaderFlags.Signed) == 0)
                {
                    if (responseShouldBeSigned)
                    {
                        throw new OpenCifsClientProtocolException(
                            $"The SMB2 response omitted the required Signed flag. Command={responseHeader.Command}; Status={responseHeader.Status}; Flags=0x{(uint)responseHeader.Flags:X8}; MessageId={responseHeader.MessageId}.",
                            nameof(responsePacket));
                    }

                    offset += entryLength;
                    continue;
                }

                byte[] signingKey = GetSessionSigningKey(GetEffectiveResponseSessionId(requestState, responseHeader));
                byte[] expectedMessage = packetBytes.Slice(offset, entryLength).ToArray();
                Array.Clear(expectedMessage, Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);
                ReadOnlySpan<byte> verifyNonce = signer.RequiresNonce
                    ? Smb2SigningNonce.BuildSmb311GmacNonce(responseHeader.MessageId, isServerToClient: true)
                    : ReadOnlySpan<byte>.Empty;

                if (!signer.Verify(expectedMessage, signingKey, verifyNonce, responseHeader.Signature))
                {
                    throw new OpenCifsClientProtocolException("The SMB2 response signature did not verify.", nameof(responsePacket));
                }

                offset += entryLength;
            }
        }

        public void ValidateOplockBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            ValidateBreakNotificationPacket(responsePacket, packetBytes, expectedStructureSize: 24, notificationName: "oplock-break");
        }

        public void ValidateLeaseBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            ValidateBreakNotificationPacket(responsePacket, packetBytes, expectedStructureSize: 44, notificationName: "lease-break");
        }

        private ulong DequeueMessageIdRange(int creditsToConsume)
        {
            ulong messageId = _PacketState.AvailableMessageIds.Dequeue();
            ulong expectedMessageId = messageId;

            for (int index = 1; index < creditsToConsume; index++)
            {
                expectedMessageId++;
                ulong consumedMessageId = _PacketState.AvailableMessageIds.Dequeue();

                if (consumedMessageId != expectedMessageId)
                {
                    throw new OpenCifsClientStateException("The local SMB2 message identifier window is not contiguous enough for the requested credit charge.");
                }
            }

            return messageId;
        }

        private int DetermineCreditsToConsume(Smb2Command command, ushort creditCharge)
        {
            if (command == Smb2Command.Cancel)
            {
                return 0;
            }

            if (command == Smb2Command.Read || command == Smb2Command.Write)
            {
                return Math.Max(1, (int)creditCharge);
            }

            return 1;
        }

        private void ValidateCompatibleCreditCharge(Smb2Command command, ushort creditCharge)
        {
            if (creditCharge == 0)
            {
                return;
            }

            SmbDialect? negotiatedDialect = _GetNegotiatedDialect();

            if (!negotiatedDialect.HasValue || negotiatedDialect.Value < SmbDialect.Smb21)
            {
                if (creditCharge > 1)
                {
                    throw new OpenCifsClientStateException("Only bounded SMB 2.1 large read and write requests may consume multiple SMB2 credits.");
                }

                return;
            }

            if (command != Smb2Command.Read && command != Smb2Command.Write && creditCharge > 1)
            {
                throw new OpenCifsClientStateException("Only bounded SMB 2.1 read and write requests may carry a multi-credit SMB2 charge.");
            }
        }

        private void GrantCredits(ushort creditCount)
        {
            _PacketState.ConnectionState.Credits.Grant(creditCount);
            ulong nextMessageIdToGrant = _PacketState.NextMessageIdToGrant;

            for (ushort index = 0; index < creditCount; index++)
            {
                _PacketState.AvailableMessageIds.Enqueue(nextMessageIdToGrant);
                nextMessageIdToGrant++;
            }

            _PacketState.NextMessageIdToGrant = nextMessageIdToGrant;
        }

        private RequestState GetPendingRequest(ulong messageId)
        {
            if (!_PacketState.PendingRequests.TryGetValue(messageId, out RequestState? requestState))
            {
                throw new OpenCifsClientProtocolException("The SMB2 response does not match any pending request on this client session.", nameof(messageId));
            }

            return requestState;
        }

        private void ValidateBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes, ushort expectedStructureSize, string notificationName)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            if (responsePacket.Entries.Count != 1)
            {
                throw new OpenCifsClientProtocolException("The managed client break-notification path expects a single SMB2 packet entry.", nameof(responsePacket));
            }

            Smb2CompoundPacketEntry entry = responsePacket.Entries[0];
            Smb2Header responseHeader = entry.Header;

            if (responseHeader.Command != Smb2Command.OplockBreak || responseHeader.MessageId != UInt64.MaxValue)
            {
                throw new OpenCifsClientProtocolException("The packet is not an unsolicited SMB2 " + notificationName + " notification.", nameof(responsePacket));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.ServerToRedir) == 0)
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification must set the ServerToRedir flag.", nameof(responsePacket));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification must not set the AsyncCommand flag.", nameof(responsePacket));
            }

            ulong? currentSessionId = _GetSessionId();

            if (currentSessionId == null ||
                (responseHeader.SessionId != 0 && responseHeader.SessionId != currentSessionId.Value))
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification session identifier is invalid.", nameof(responsePacket));
            }

            byte[] payload = entry.Payload;

            if (payload.Length < 2)
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification payload is truncated.", nameof(responsePacket));
            }

            LittleEndianReader payloadReader = new LittleEndianReader(payload);

            if (payloadReader.ReadUInt16() != expectedStructureSize)
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification structure size is invalid.", nameof(responsePacket));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.Signed) == 0)
            {
                return;
            }

            if (responseHeader.SessionId == 0)
            {
                return;
            }

            IMessageSigner signer = OpenCifsClientSessionProtocolSupport.CreateNegotiatedMessageSigner(_GetNegotiatedDialect());
            byte[] signingKey = GetSessionSigningKey(responseHeader.SessionId);
            byte[] expectedMessage = packetBytes.ToArray();
            Array.Clear(expectedMessage, Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);
            ReadOnlySpan<byte> notificationVerifyNonce = signer.RequiresNonce
                ? Smb2SigningNonce.BuildSmb311GmacNonce(responseHeader.MessageId, isServerToClient: true)
                : ReadOnlySpan<byte>.Empty;

            if (!signer.Verify(expectedMessage, signingKey, notificationVerifyNonce, responseHeader.Signature))
            {
                throw new OpenCifsClientProtocolException("The unsolicited SMB2 " + notificationName + " notification signature did not verify.", nameof(responsePacket));
            }
        }

        private bool ShouldSignCommand(Smb2Command command, ulong sessionId)
        {
            return _GetIsSigningRequired() &&
                _GetSessionState().IsAuthenticated &&
                !IsSessionEncryptionActive(sessionId) &&
                sessionId != 0 &&
                command != Smb2Command.Negotiate &&
                command != Smb2Command.SessionSetup;
        }

        private bool ShouldRequireSignedResponse(RequestState requestState, Smb2Header responseHeader)
        {
            if ((responseHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0 &&
                responseHeader.Status == NtStatus.Pending)
            {
                return false;
            }

            Smb2HeaderFlags requestFlags = requestState.Header != null
                ? requestState.Header.Flags
                : Smb2HeaderFlags.None;

            if ((requestFlags & Smb2HeaderFlags.Signed) != 0)
            {
                return true;
            }

            ulong effectiveSessionId = GetEffectiveResponseSessionId(requestState, responseHeader);
            if (IsSessionEncryptionActive(effectiveSessionId))
            {
                return false;
            }

            return _GetIsSigningRequired() &&
                effectiveSessionId != 0 &&
                responseHeader.Command != Smb2Command.Negotiate &&
                responseHeader.Command != Smb2Command.SessionSetup;
        }

        private ulong GetEffectiveResponseSessionId(RequestState requestState, Smb2Header responseHeader)
        {
            if (responseHeader.SessionId != 0)
            {
                return responseHeader.SessionId;
            }

            return requestState.Header?.SessionId ?? 0;
        }

        private byte[] GetSessionSigningKey(ulong sessionId)
        {
            if (sessionId == 0)
            {
                throw new OpenCifsClientStateException("A non-zero session identifier is required before SMB2 signing keys can be used.");
            }

            byte[]? sessionSigningKey = _GetSessionSigningKey();
            if (sessionSigningKey == null || sessionSigningKey.Length == 0)
            {
                throw new OpenCifsClientStateException("The client does not have a signing key for the authenticated SMB2 session.");
            }

            if (!_GetSessionState().IsAuthenticated || _GetSessionId() != sessionId)
            {
                throw new OpenCifsClientStateException("The client does not have an authenticated SMB2 session for the supplied signing key request.");
            }

            return sessionSigningKey;
        }

        private byte[] GetSessionEncryptionKey(ulong sessionId)
        {
            byte[]? sessionEncryptionKey = _GetSessionEncryptionKey();

            if (!IsSessionEncryptionActive(sessionId) || sessionEncryptionKey == null || sessionEncryptionKey.Length == 0)
            {
                throw new OpenCifsClientStateException("The client does not have an outbound SMB3 encryption key for the authenticated session.");
            }

            return sessionEncryptionKey;
        }

        private byte[] GetSessionDecryptionKey(ulong sessionId)
        {
            byte[]? sessionDecryptionKey = _GetSessionDecryptionKey();

            if (!IsSessionEncryptionActive(sessionId) || sessionDecryptionKey == null || sessionDecryptionKey.Length == 0)
            {
                throw new OpenCifsClientStateException("The client does not have an inbound SMB3 decryption key for the authenticated session.");
            }

            return sessionDecryptionKey;
        }

        private bool IsSessionEncryptionActive(ulong sessionId)
        {
            SmbDialect? negotiatedDialect = _GetNegotiatedDialect();

            return _GetIsSessionEncryptionRequired() &&
                _GetSessionState().IsAuthenticated &&
                sessionId != 0 &&
                _GetSessionId() == sessionId &&
                negotiatedDialect.HasValue &&
                negotiatedDialect.Value >= SmbDialect.Smb30 &&
                (_GetNegotiatedServerCapabilities() & Smb2GlobalCapabilities.Encryption) != 0;
        }

        private bool TryGetEncryptedPacketSessionId(Smb2CompoundPacket requestPacket, out ulong sessionId)
        {
            sessionId = 0;

            if (!_GetIsSessionEncryptionRequired() || requestPacket.Entries.Count == 0)
            {
                return false;
            }

            ulong candidateSessionId = requestPacket.Entries[0].Header.SessionId;

            if (!IsSessionEncryptionActive(candidateSessionId))
            {
                return false;
            }

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2Header header = requestPacket.Entries[index].Header;

                if (header.SessionId != candidateSessionId)
                {
                    throw new OpenCifsClientStateException("The bounded SMB3 encrypted packet path does not support compounded requests that mix SMB2 session identifiers.");
                }

                if (header.Command == Smb2Command.Negotiate || header.Command == Smb2Command.SessionSetup)
                {
                    throw new OpenCifsClientStateException("The bounded SMB3 encrypted packet path does not support encrypting negotiate or session-setup requests.");
                }
            }

            sessionId = candidateSessionId;
            return true;
        }

        private readonly OpenCifsClientSessionPacketState _PacketState;
        private readonly Func<SessionState> _GetSessionState;
        private readonly Func<ulong?> _GetSessionId;
        private readonly Func<SmbDialect?> _GetNegotiatedDialect;
        private readonly Func<bool> _GetIsAuthenticated;
        private readonly Func<bool> _GetIsSigningRequired;
        private readonly Func<Smb2GlobalCapabilities> _GetNegotiatedServerCapabilities;
        private readonly Func<SmbCipherAlgorithmId> _GetNegotiatedCipher;
        private readonly Func<byte[]?> _GetSessionSigningKey;
        private readonly Func<byte[]?> _GetSessionEncryptionKey;
        private readonly Func<byte[]?> _GetSessionDecryptionKey;
        private readonly Func<bool> _GetIsSessionEncryptionRequired;
    }
}

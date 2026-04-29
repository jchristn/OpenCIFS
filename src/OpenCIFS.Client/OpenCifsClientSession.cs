namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    /// <summary>
        /// Low-level client session state for the currently implemented SMB 2.1-or-earlier negotiate, session, tree, and file-I/O slices.
    /// </summary>
    public sealed class OpenCifsClientSession
    {
        private const uint DefaultDesiredAccess = 0xC0000000U;
        private const uint DefaultShareAccess = 0x00000007U;
        private const ulong WildcardIoctlFileId = UInt64.MaxValue;
        private const int Smb2HeaderSignatureOffset = 48;
        private const int Smb2HeaderSignatureLength = 16;

        private readonly ConnectionState _ConnectionState = new ConnectionState();
        private SessionState _SessionState = new SessionState();
        private readonly Queue<ulong> _AvailableMessageIds = new Queue<ulong>();
        private readonly Dictionary<ulong, RequestState> _PendingRequests = new Dictionary<ulong, RequestState>();
        private readonly Dictionary<uint, TreeConnectState> _Trees = new Dictionary<uint, TreeConnectState>();
        private readonly Dictionary<ulong, ClientOpenRecord> _Opens = new Dictionary<ulong, ClientOpenRecord>();
        private SmbDialect[]? _LastOfferedDialects;
        private byte[]? _SessionBaseKey;
        private byte[]? _SessionSigningKey;
        private byte[]? _StandardNegotiateMessage;
        private ulong? _SessionId;
        private ulong _NextMessageIdToGrant = 1;

        /// <summary>
        /// Initialize a client session.
        /// </summary>
        /// <param name="options">Client options.</param>
        public OpenCifsClientSession(OpenCifsClientOptions options)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            Options.Validate();
            ClientGuid = Guid.NewGuid();
            _AvailableMessageIds.Enqueue(0);
            _ConnectionState.Credits.Grant(1);
        }

        /// <summary>
        /// Client options.
        /// </summary>
        public OpenCifsClientOptions Options { get; }

        /// <summary>
        /// Client GUID advertised during negotiation.
        /// </summary>
        public Guid ClientGuid { get; }

        /// <summary>
        /// Negotiated dialect after a successful response.
        /// </summary>
        public SmbDialect? NegotiatedDialect { get; private set; }

        /// <summary>
        /// Negotiated server GUID after a successful response.
        /// </summary>
        public Guid? ServerGuid { get; private set; }

        /// <summary>
        /// Negotiated maximum transact size.
        /// </summary>
        public uint NegotiatedMaxTransactSize { get; private set; }

        /// <summary>
        /// Negotiated maximum read size.
        /// </summary>
        public uint NegotiatedMaxReadSize { get; private set; }

        /// <summary>
        /// Negotiated maximum write size.
        /// </summary>
        public uint NegotiatedMaxWriteSize { get; private set; }

        /// <summary>
        /// Whether signing is required for the current negotiated session.
        /// </summary>
        public bool IsSigningRequired { get; private set; }

        /// <summary>
        /// Whether the session completed negotiate successfully.
        /// </summary>
        public bool IsNegotiated
        {
            get
            {
                return NegotiatedDialect.HasValue;
            }
        }

        /// <summary>
        /// Current session identifier after session setup begins.
        /// </summary>
        public ulong? SessionId
        {
            get
            {
                return _SessionId;
            }
            private set
            {
                _SessionId = value;
            }
        }

        /// <summary>
        /// Whether the session completed authentication successfully.
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return _SessionState.IsAuthenticated;
            }
        }

        /// <summary>
        /// Currently connected tree identifiers.
        /// </summary>
        public uint[] ConnectedTreeIds
        {
            get
            {
                uint[] treeIds = new uint[_Trees.Count];
                _Trees.Keys.CopyTo(treeIds, 0);
                Array.Sort(treeIds);
                return treeIds;
            }
        }

        /// <summary>
        /// Currently tracked client open count.
        /// </summary>
        public int OpenCount
        {
            get
            {
                return _Opens.Count;
            }
        }

        /// <summary>
        /// Currently available SMB2 request credits.
        /// </summary>
        public int AvailableCredits
        {
            get
            {
                return _ConnectionState.Credits.AvailableCredits;
            }
        }

        /// <summary>
        /// Currently pending SMB2 requests awaiting response headers.
        /// </summary>
        public int PendingRequestCount
        {
            get
            {
                return _PendingRequests.Count;
            }
        }

        /// <summary>
        /// Get the SMB2 credits required to carry a bounded read or write of the supplied length.
        /// </summary>
        /// <param name="length">Requested byte count.</param>
        /// <returns>Credits required for the request.</returns>
        public ushort GetRequiredReadWriteCredits(uint length)
        {
            return Smb2CreditChargeHelper.GetRequiredReadWriteCredits(NegotiatedDialect, length);
        }

        /// <summary>
        /// Get the SMB2 header credit charge for a bounded read or write of the supplied length.
        /// </summary>
        /// <param name="length">Requested byte count.</param>
        /// <returns>Header credit charge.</returns>
        public ushort GetReadWriteCreditCharge(uint length)
        {
            return Smb2CreditChargeHelper.GetReadWriteCreditCharge(NegotiatedDialect, length);
        }

        /// <summary>
        /// Get the dialects currently advertised by this client session.
        /// </summary>
        /// <returns>Advertised SMB2/3 dialects.</returns>
        public SmbDialect[] GetAdvertisedDialects()
        {
            SmbDialect maximumImplementedDialect = SmbDialect.Smb21;
            SmbDialect effectiveMaximumDialect = Options.MaximumDialect < maximumImplementedDialect
                ? Options.MaximumDialect
                : maximumImplementedDialect;

            if (effectiveMaximumDialect < Options.MinimumDialect)
            {
                return Array.Empty<SmbDialect>();
            }

            return SmbDialectCatalog.GetSmb2DialectsInRange(Options.MinimumDialect, effectiveMaximumDialect);
        }

        /// <summary>
        /// Create an SMB2 request header and reserve one credit plus one message identifier from the local sequence window.
        /// </summary>
        /// <param name="command">SMB2 command identifier.</param>
        /// <param name="treeId">Tree identifier for tree-scoped requests.</param>
        /// <param name="creditRequest">Credits requested from the server response.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>65535</c>.</param>
        /// <param name="sessionId">Optional session identifier override for requests that must carry a server-assigned session before the local authenticated state is fully applied.</param>
        /// <param name="creditCharge">Optional SMB2 credit charge for bounded SMB 2.1 large read and write requests.</param>
        /// <returns>Request header for the outbound SMB2 message.</returns>
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

            ulong effectiveSessionId = sessionId ?? (command == Smb2Command.Negotiate ? 0UL : SessionId ?? 0UL);

            if (treeId != 0 && effectiveSessionId == 0)
            {
                throw new InvalidOperationException("A non-zero tree identifier requires a session-scoped SMB2 request.");
            }

            ValidateCompatibleCreditCharge(command, creditCharge);
            int creditsToConsume = DetermineCreditsToConsume(command, creditCharge);

            if (_AvailableMessageIds.Count < creditsToConsume)
            {
                throw new InvalidOperationException("The local SMB2 message identifier window does not have enough contiguous sequence numbers for the outbound request.");
            }

            _ConnectionState.Credits.Consume(creditsToConsume);
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
            _PendingRequests[messageId] = requestState;
            return header;
        }

        /// <summary>
        /// Create an SMB2 cancel request body.
        /// </summary>
        /// <returns>Cancel request.</returns>
        public Smb2CancelRequest CreateCancelRequest()
        {
            Smb2CancelRequest request = new Smb2CancelRequest();
            Smb2CancelRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Create an SMB2 cancel request header for a currently pending SMB2 request.
        /// </summary>
        /// <param name="messageId">Pending request message identifier.</param>
        /// <returns>Request header for the outbound SMB2 cancel message.</returns>
        public Smb2Header CreateCancelRequestHeader(ulong messageId)
        {
            if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState) || requestState.Header == null)
            {
                throw new InvalidOperationException("The specified SMB2 message identifier is not currently pending on this client session.");
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

        /// <summary>
        /// Create an SMB2 request header for a related compounded operation.
        /// </summary>
        /// <param name="command">SMB2 command identifier.</param>
        /// <param name="treeId">Optional tree identifier to place in the header.</param>
        /// <param name="creditRequest">Credits requested from the server response.</param>
        /// <param name="sessionId">Optional session identifier override.</param>
        /// <returns>Request header for a related compounded SMB2 message.</returns>
        public Smb2Header CreateRelatedRequestHeader(Smb2Command command, uint treeId = 0, ushort creditRequest = 1, ulong? sessionId = null)
        {
            Smb2Header header = CreateRequestHeader(command, treeId, creditRequest, sessionId);
            header.Flags = Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(header);
            return header;
        }

        /// <summary>
        /// Apply an SMB2 response header, validate its message binding, and return granted credits to the local sequence window.
        /// </summary>
        /// <param name="responseHeader">Response header from the server.</param>
        public void ApplyResponseHeader(Smb2Header responseHeader)
        {
            if (responseHeader == null)
            {
                throw new ArgumentNullException(nameof(responseHeader), "ResponseHeader cannot be null.");
            }

            Smb2HeaderValidator.Validate(responseHeader);

            if ((responseHeader.Flags & Smb2HeaderFlags.ServerToRedir) == 0)
            {
                throw new ProtocolValidationException("SMB2 response headers must set the ServerToRedir flag.", nameof(responseHeader));
            }

            Smb2HeaderFlags unsupportedFlags = responseHeader.Flags & ~(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.Signed | Smb2HeaderFlags.RelatedOperations | Smb2HeaderFlags.AsyncCommand);

            if (unsupportedFlags != Smb2HeaderFlags.None)
            {
                throw new ProtocolValidationException("The response header contains SMB2 flags that are not supported in the current SMB 2.0.2 slice.", nameof(responseHeader));
            }

            RequestState requestState = GetPendingRequest(responseHeader.MessageId);

            if (requestState.Command != responseHeader.Command)
            {
                throw new ProtocolValidationException("The SMB2 response command does not match the pending request.", nameof(responseHeader));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                if ((responseHeader.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
                {
                    throw new ProtocolValidationException("Async SMB2 responses are not supported inside related compounded chains in the current slice.", nameof(responseHeader));
                }

                if (responseHeader.Status == NtStatus.Pending)
                {
                    if (responseHeader.CreditRequest == 0)
                    {
                        throw new ProtocolValidationException("Interim async SMB2 responses must grant at least one credit.", nameof(responseHeader));
                    }

                    GrantCredits(responseHeader.CreditRequest);
                    requestState.MarkAsync(responseHeader.AsyncId);
                    return;
                }

                if (responseHeader.CreditRequest != 0)
                {
                    throw new ProtocolValidationException("Final async SMB2 responses must not grant additional credits in the current slice.", nameof(responseHeader));
                }

                if (requestState.AsyncId == 0 || requestState.AsyncId != responseHeader.AsyncId)
                {
                    throw new ProtocolValidationException("The async SMB2 response does not match the pending request AsyncId.", nameof(responseHeader));
                }
            }
            else
            {
                if (responseHeader.CreditRequest == 0)
                {
                    throw new ProtocolValidationException("SMB 2.0.2 synchronous response headers must grant at least one credit.", nameof(responseHeader));
                }

                GrantCredits(responseHeader.CreditRequest);
            }

            requestState.Complete();
            requestState.Dispose();
            _PendingRequests.Remove(responseHeader.MessageId);
        }

        /// <summary>
        /// Apply the headers from an SMB2 compounded response packet in wire order.
        /// </summary>
        /// <param name="responsePacket">Compounded response packet.</param>
        public void ApplyCompoundResponsePacket(Smb2CompoundPacket responsePacket)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            IReadOnlyList<Smb2CompoundPacketEntry> entries = responsePacket.Entries;

            for (int index = 0; index < entries.Count; index++)
            {
                ApplyResponseHeader(entries[index].Header);
            }
        }

        /// <summary>
        /// Serialize an SMB2 request packet and sign any entries that require SMB2 signing in the current session.
        /// </summary>
        /// <param name="requestPacket">Request packet to serialize.</param>
        /// <returns>Serialized packet bytes with any applicable SMB2 signatures applied.</returns>
        public byte[] FinalizeRequestPacket(Smb2CompoundPacket requestPacket)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            byte[] packetBytes = requestPacket.ToByteArray();
            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
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
                    byte[] signature = signer.Sign(packetBytes.AsSpan(offset, entryLength), signingKey, ReadOnlySpan<byte>.Empty);
                    Buffer.BlockCopy(signature, 0, packetBytes, offset + Smb2HeaderSignatureOffset, signature.Length);
                }

                offset += entryLength;
            }

            return packetBytes;
        }

        /// <summary>
        /// Validate SMB2 response signatures for a serialized packet against the current client session state.
        /// </summary>
        /// <param name="responsePacket">Parsed SMB2 response packet.</param>
        /// <param name="packetBytes">Serialized SMB2 response bytes.</param>
        public void ValidateResponsePacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
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
                        throw new ProtocolValidationException(
                            $"The SMB2 response omitted the required Signed flag. Command={responseHeader.Command}; Status={responseHeader.Status}; Flags=0x{(uint)responseHeader.Flags:X8}; MessageId={responseHeader.MessageId}.",
                            nameof(responsePacket));
                    }

                    offset += entryLength;
                    continue;
                }

                byte[] signingKey = GetSessionSigningKey(GetEffectiveResponseSessionId(requestState, responseHeader));
                byte[] expectedMessage = packetBytes.Slice(offset, entryLength).ToArray();
                Array.Clear(expectedMessage, Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);

                if (!signer.Verify(expectedMessage, signingKey, ReadOnlySpan<byte>.Empty, responseHeader.Signature))
                {
                    throw new ProtocolValidationException("The SMB2 response signature did not verify.", nameof(responsePacket));
                }

                offset += entryLength;
            }
        }

        /// <summary>
        /// Validate an unsolicited SMB2 oplock-break notification packet.
        /// </summary>
        /// <param name="responsePacket">Parsed SMB2 packet.</param>
        /// <param name="packetBytes">Serialized SMB2 packet bytes.</param>
        public void ValidateOplockBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            ValidateBreakNotificationPacket(responsePacket, packetBytes, expectedStructureSize: 24, notificationName: "oplock-break");
        }

        /// <summary>
        /// Validate an unsolicited SMB2 lease-break notification packet.
        /// </summary>
        /// <param name="responsePacket">Parsed SMB2 packet.</param>
        /// <param name="packetBytes">Serialized SMB2 packet bytes.</param>
        public void ValidateLeaseBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes)
        {
            ValidateBreakNotificationPacket(responsePacket, packetBytes, expectedStructureSize: 44, notificationName: "lease-break");
        }

        /// <summary>
        /// Create an SMB2 negotiate request for the currently implemented dialect slice.
        /// </summary>
        /// <returns>Negotiate request.</returns>
        public Smb2NegotiateRequest CreateNegotiateRequest()
        {
            SmbDialect[] advertisedDialects = GetAdvertisedDialects();

            if (advertisedDialects.Length == 0)
            {
                throw new InvalidOperationException("The configured client dialect range does not include any currently implemented SMB2 dialects.");
            }

            Smb2SecurityMode securityMode = Smb2SecurityMode.SigningEnabled;

            if (Options.RequireSigning)
            {
                securityMode |= Smb2SecurityMode.SigningRequired;
            }

            Smb2NegotiateRequest request = new Smb2NegotiateRequest
            {
                SecurityMode = securityMode,
                Capabilities = Smb2GlobalCapabilities.None,
                ClientGuid = ClientGuid,
                ClientStartTime = 0,
                Dialects = advertisedDialects
            };

            Smb2NegotiateRequestValidator.Validate(request);
            _LastOfferedDialects = advertisedDialects;
            return request;
        }

        /// <summary>
        /// Apply an SMB2 negotiate response to this client session.
        /// </summary>
        /// <param name="response">Server negotiate response.</param>
        public void ApplyNegotiateResponse(Smb2NegotiateResponse response)
        {
            if (_LastOfferedDialects == null)
            {
                throw new InvalidOperationException("A negotiate request must be created before a response can be applied.");
            }

            Smb2NegotiateResponseValidator.Validate(response);

            if (!ContainsDialect(_LastOfferedDialects, response.Dialect))
            {
                throw new InvalidOperationException("The server selected a dialect that the client did not advertise.");
            }

            if (response.Dialect < Options.MinimumDialect || response.Dialect > Options.MaximumDialect)
            {
                throw new InvalidOperationException("The negotiated dialect is outside the configured client dialect range.");
            }

            if ((response.SecurityMode & Smb2SecurityMode.SigningEnabled) == 0)
            {
                throw new InvalidOperationException("The server negotiate response must enable message signing.");
            }

            NegotiatedDialect = response.Dialect;
            ServerGuid = response.ServerGuid;
            NegotiatedMaxTransactSize = response.MaxTransactSize;
            NegotiatedMaxReadSize = response.MaxReadSize;
            NegotiatedMaxWriteSize = response.MaxWriteSize;
            IsSigningRequired = Options.RequireSigning || (response.SecurityMode & Smb2SecurityMode.SigningRequired) != 0;
            _ConnectionState.Negotiate(response.Dialect);
        }

        /// <summary>
        /// Create the first SMB2 session-setup request for SPNEGO-wrapped NTLM negotiation.
        /// </summary>
        /// <param name="credential">Client credential material.</param>
        /// <returns>Session-setup request.</returns>
        public Smb2SessionSetupRequest CreateSessionSetupRequest(OpenCifsClientCredential credential)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            if (!IsNegotiated)
            {
                throw new InvalidOperationException("Negotiate must complete before session setup can begin.");
            }

            NtlmNegotiateMessage mechanismToken = CreateStandardNegotiateMessage(credential);
            byte[] negotiateMessageBytes = mechanismToken.ToByteArray();
            _StandardNegotiateMessage = (byte[])negotiateMessageBytes.Clone();

            SpnegoNegTokenInit initToken = new SpnegoNegTokenInit
            {
                MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm },
                MechanismToken = negotiateMessageBytes
            };

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                Flags = 0,
                SecurityMode = IsSigningRequired
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

        /// <summary>
        /// Create the second SMB2 session-setup request that answers the server challenge.
        /// </summary>
        /// <param name="credential">Client credential material.</param>
        /// <param name="sessionId">Server-assigned session identifier from the first leg.</param>
        /// <param name="status">NTSTATUS from the first session-setup response.</param>
        /// <param name="challengeResponse">Server challenge response body from the first leg.</param>
        /// <returns>Authentication request.</returns>
        public Smb2SessionSetupRequest CreateSessionAuthenticateRequest(OpenCifsClientCredential credential, ulong sessionId, NtStatus status, Smb2SessionSetupResponse challengeResponse)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            if (!IsNegotiated)
            {
                throw new InvalidOperationException("Negotiate must complete before session authentication can continue.");
            }

            if (status != NtStatus.MoreProcessingRequired)
            {
                throw new InvalidOperationException("The server did not return an SMB2 session-setup challenge.");
            }

            if (challengeResponse == null)
            {
                throw new ArgumentNullException(nameof(challengeResponse), "ChallengeResponse cannot be null.");
            }

            Smb2SessionSetupResponseValidator.Validate(challengeResponse);

            if (sessionId == 0)
            {
                throw new InvalidOperationException("The server challenge did not include a valid session identifier.");
            }

            if (challengeResponse.SecurityBuffer.Length == 0)
            {
                throw new InvalidOperationException("The server challenge did not include a security buffer.");
            }

            if (TryExtractStandardChallengeToken(challengeResponse.SecurityBuffer, out byte[]? challengeTokenBytes, out bool wrapAuthenticateInSpnego) &&
                challengeTokenBytes != null)
            {
                NtlmChallengeMessage challengeMessage;

                try
                {
                    challengeMessage = NtlmChallengeMessage.ReadFrom(challengeTokenBytes);
                }
                catch (ProtocolEncodingException exception)
                {
                    throw new InvalidOperationException("The server challenge token is not a valid NTLM challenge message.", exception);
                }

                if (_StandardNegotiateMessage == null || _StandardNegotiateMessage.Length == 0)
                {
                    throw new InvalidOperationException("The client does not have the original NTLM negotiate message for session authentication.");
                }

                NtlmV2ClientChallenge clientChallenge = CreateStandardClientChallenge(challengeMessage);
                NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                    password: credential.Password,
                    userName: credential.UserName,
                    userDomain: credential.UserDomain,
                    serverChallenge: challengeMessage.ServerChallenge,
                    clientChallenge: clientChallenge);

                _SessionBaseKey = responseSet.SessionBaseKey;
                _SessionSigningKey = responseSet.SessionBaseKey;
                SessionId = sessionId;

                NtlmAuthenticateMessage standardAuthenticateToken = new NtlmAuthenticateMessage
                {
                    Flags = DetermineStandardAuthenticateFlags(challengeMessage.Flags),
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
                    negotiateMessage: _StandardNegotiateMessage,
                    challengeMessage: challengeTokenBytes,
                    authenticateMessageWithZeroMic: authenticateTokenBytesWithZeroMic);
                byte[] authenticateTokenBytes = standardAuthenticateToken.ToByteArray();

                Smb2SessionSetupRequest standardRequest = new Smb2SessionSetupRequest
                {
                    Flags = 0,
                    SecurityMode = IsSigningRequired
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
                throw new InvalidOperationException("The server challenge security buffer is not a valid SPNEGO response token.", exception);
            }

            if (responseToken.NegotiationState != SpnegoNegState.AcceptIncomplete)
            {
                throw new InvalidOperationException("The server challenge must report an incomplete SPNEGO negotiation state.");
            }

            if (!string.Equals(responseToken.SupportedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The server selected an unsupported SPNEGO mechanism.");
            }

            if (responseToken.ResponseToken == null)
            {
                throw new InvalidOperationException("The server challenge is missing the NTLM response token.");
            }

            OpenCifsNtlmChallengeToken legacyChallengeToken;

            try
            {
                legacyChallengeToken = OpenCifsNtlmChallengeToken.ReadFrom(responseToken.ResponseToken);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new InvalidOperationException("The server challenge token is not a valid OpenCIFS NTLM challenge token.", exception);
            }

            NtlmV2ClientChallenge legacyClientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = unchecked((ulong)DateTime.UtcNow.ToFileTimeUtc()),
                ClientChallenge = CreateRandomBytes(8),
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

            _SessionBaseKey = legacyResponseSet.SessionBaseKey;
            _SessionSigningKey = legacyResponseSet.SessionBaseKey;
            SessionId = sessionId;

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
                SecurityMode = IsSigningRequired
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

        /// <summary>
        /// Apply a successful SMB2 session-setup result.
        /// </summary>
        /// <param name="sessionId">Server-assigned session identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server session-setup response body.</param>
        public void ApplySessionSetupResult(ulong sessionId, NtStatus status, Smb2SessionSetupResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.SessionSetup, status);
            }

            if (_SessionBaseKey == null || _SessionBaseKey.Length == 0)
            {
                throw new InvalidOperationException("The client does not have a session base key for the authenticated session.");
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2SessionSetupResponseValidator.Validate(response);

            if (sessionId == 0)
            {
                throw new InvalidOperationException("The server did not return a valid session identifier.");
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
                    throw new InvalidOperationException("The server session-setup response is not a valid SPNEGO response token.", exception);
                }

                if (responseToken.NegotiationState != SpnegoNegState.AcceptCompleted)
                {
                    throw new InvalidOperationException("The server session-setup response did not complete SPNEGO negotiation.");
                }

                if (!string.IsNullOrEmpty(responseToken.SupportedMechanism) &&
                    !string.Equals(responseToken.SupportedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The server completed session setup with an unsupported mechanism.");
                }
            }

            if (_SessionState.SessionId == 0)
            {
                _SessionState.Bind(sessionId);
            }

            _SessionState.Authenticate();
            SessionId = sessionId;
        }

        /// <summary>
        /// Create an SMB2 echo request for the authenticated session.
        /// </summary>
        /// <returns>Echo request.</returns>
        public Smb2EchoRequest CreateEchoRequest()
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before echo.");
            }

            Smb2EchoRequest request = new Smb2EchoRequest();
            Smb2EchoRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply a successful SMB2 echo result.
        /// </summary>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server echo response body.</param>
        public void ApplyEchoResult(NtStatus status, Smb2EchoResponse response)
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before echo responses can be applied.");
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

        /// <summary>
        /// Create an SMB2 tree-connect request for a share on the negotiated server.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <returns>Tree-connect request.</returns>
        public Smb2TreeConnectRequest CreateTreeConnectRequest(string shareName)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before tree connect.");
            }

            Smb2TreeConnectRequest request = new Smb2TreeConnectRequest
            {
                Flags = 0,
                Path = "\\\\" + Options.ServerName + "\\" + shareName.Trim('\\')
            };

            Smb2TreeConnectRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply a successful SMB2 tree-connect result.
        /// </summary>
        /// <param name="shareName">Share name used in the request.</param>
        /// <param name="treeId">Server-assigned tree identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server tree-connect response body.</param>
        public void ApplyTreeConnectResult(string shareName, uint treeId, NtStatus status, Smb2TreeConnectResponse response)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.TreeConnect, status);
            }

            if (treeId == 0)
            {
                throw new InvalidOperationException("The server did not assign a valid tree identifier.");
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2TreeConnectResponseValidator.Validate(response);

            TreeConnectState treeState = new TreeConnectState();
            treeState.Connect(treeId, shareName.Trim('\\'));
            _Trees[treeId] = treeState;
        }

        /// <summary>
        /// Create an SMB2 create request for a connected tree.
        /// </summary>
        /// <param name="treeId">Tree identifier.</param>
        /// <param name="path">Relative path within the connected share.</param>
        /// <param name="desiredAccess">Desired access mask.</param>
        /// <param name="fileAttributes">Requested file attributes.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition.</param>
        /// <param name="createOptions">Create options.</param>
        /// <param name="requestedOplockLevel">Requested oplock level.</param>
        /// <param name="requestDurableHandle">Whether to append a bounded SMB 2.0.2 durable-handle request context.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key. When omitted, a random key is generated.</param>
        /// <returns>Create request.</returns>
        public Smb2CreateRequest CreateCreateRequest(
            uint treeId,
            string path,
            uint desiredAccess = DefaultDesiredAccess,
            FileAttributes fileAttributes = FileAttributes.Normal,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.OpenIf,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            Smb2OplockLevel requestedOplockLevel = Smb2OplockLevel.None,
            bool requestDurableHandle = false,
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.None,
            byte[]? leaseKey = null)
        {
            List<Smb2CreateContext> createContexts = new List<Smb2CreateContext>();

            if (requestDurableHandle)
            {
                createContexts.Add(Smb2DurableHandleRequestContext.Create());
            }

            if (requestedOplockLevel == Smb2OplockLevel.Lease)
            {
                Smb2LeaseState effectiveLeaseState = requestedLeaseState == Smb2LeaseState.None
                    ? Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                    : requestedLeaseState;
                byte[] effectiveLeaseKey = CreateLeaseKey(leaseKey);
                createContexts.Add(new Smb2CreateRequestLeaseContext
                {
                    LeaseKey = effectiveLeaseKey,
                    LeaseState = effectiveLeaseState
                }.ToCreateContext());
            }

            return CreateCreateRequestCore(
                treeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                createContexts.Count == 0
                    ? Array.Empty<byte>()
                    : Smb2CreateContextCodec.Encode(createContexts));
        }

        /// <summary>
        /// Create an SMB2 durable reconnect request for a previously granted durable open.
        /// </summary>
        /// <param name="treeId">Tree identifier.</param>
        /// <param name="path">Relative path within the connected share.</param>
        /// <param name="persistentFileId">Persistent file identifier from the original durable open.</param>
        /// <param name="volatileFileId">Volatile file identifier from the original durable open.</param>
        /// <param name="desiredAccess">Desired access mask.</param>
        /// <param name="fileAttributes">Requested file attributes.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition.</param>
        /// <param name="createOptions">Create options.</param>
        /// <param name="requestedOplockLevel">Requested oplock level.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key for a lease-backed reconnect request.</param>
        /// <returns>Create request.</returns>
        public Smb2CreateRequest CreateDurableReconnectCreateRequest(
            uint treeId,
            string path,
            ulong persistentFileId,
            ulong volatileFileId,
            uint desiredAccess = DefaultDesiredAccess,
            FileAttributes fileAttributes = FileAttributes.Normal,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.Open,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            Smb2OplockLevel requestedOplockLevel = Smb2OplockLevel.Batch,
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.None,
            byte[]? leaseKey = null)
        {
            List<Smb2CreateContext> createContexts = new List<Smb2CreateContext>
            {
                new Smb2DurableHandleReconnectContext
                {
                    PersistentFileId = persistentFileId,
                    VolatileFileId = volatileFileId
                }.ToCreateContext()
            };

            if (requestedOplockLevel == Smb2OplockLevel.Lease && leaseKey != null)
            {
                createContexts.Add(new Smb2CreateRequestLeaseContext
                {
                    LeaseKey = CreateLeaseKey(leaseKey),
                    LeaseState = requestedLeaseState == Smb2LeaseState.None
                        ? Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                        : requestedLeaseState
                }.ToCreateContext());
            }

            return CreateCreateRequestCore(
                treeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                Smb2CreateContextCodec.Encode(createContexts));
        }

        /// <summary>
        /// Apply a successful SMB2 create result and track the returned open.
        /// </summary>
        /// <param name="treeId">Tree identifier associated with the request.</param>
        /// <param name="path">Relative path used for the request.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server create response body.</param>
        /// <returns>Tracked open state.</returns>
        public OpenState ApplyCreateResult(uint treeId, string path, NtStatus status, Smb2CreateResponse response)
        {
            EnsureConnectedTree(treeId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Create, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2CreateResponseValidator.Validate(response);
            string normalizedPath = NormalizeOpenPath(path);
            bool durableGranted = false;
            Smb2CreateResponseLeaseContext? leaseResponseContext = null;

            Smb2CreateContext[] createContexts = Smb2CreateContextCodec.Decode(response.CreateContexts);

            for (int index = 0; index < createContexts.Length; index++)
            {
                if (Smb2DurableHandleResponseContext.IsMatch(createContexts[index]))
                {
                    durableGranted = true;
                    continue;
                }

                if (Smb2CreateResponseLeaseContext.IsMatch(createContexts[index]))
                {
                    leaseResponseContext = Smb2CreateResponseLeaseContext.ReadFrom(createContexts[index]);
                }
            }

            OpenState openState = new OpenState();
            openState.Bind(response.PersistentFileId, response.VolatileFileId, normalizedPath);
            openState.SetOplockLevel(response.OplockLevel);
            openState.SetDurable(durableGranted);

            if (leaseResponseContext != null)
            {
                openState.SetLease(leaseResponseContext.LeaseKey, leaseResponseContext.LeaseState);
            }

            if (_Opens.TryGetValue(response.VolatileFileId, out ClientOpenRecord? existingRecord))
            {
                existingRecord.State.Dispose();
            }

            _Opens[response.VolatileFileId] = new ClientOpenRecord
            {
                TreeId = treeId,
                State = openState
            };

            return openState;
        }

        private Smb2CreateRequest CreateCreateRequestCore(
            uint treeId,
            string path,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel,
            byte[] createContexts)
        {
            EnsureConnectedTree(treeId);
            string normalizedPath = NormalizeOpenPath(path);

            Smb2CreateRequest request = new Smb2CreateRequest
            {
                RequestedOplockLevel = requestedOplockLevel,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                Name = normalizedPath,
                CreateContexts = createContexts ?? Array.Empty<byte>()
            };

            Smb2CreateRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Create an SMB2 lease-break acknowledgment request for a tracked lease-backed open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <returns>Lease-break acknowledgment request.</returns>
        public Smb2LeaseBreakAcknowledgment CreateLeaseBreakAcknowledgmentRequest(ulong persistentFileId, ulong volatileFileId)
        {
            ClientOpenRecord openRecord = GetTrackedOpen(persistentFileId, volatileFileId);

            if (openRecord.State.LeaseKey.Length != 16)
            {
                throw new InvalidOperationException("The specified file identifier is not tracked as an SMB 2.1 lease-backed open.");
            }

            Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
            {
                LeaseKey = (byte[])openRecord.State.LeaseKey.Clone(),
                LeaseState = openRecord.State.LeaseState
            };
            Smb2LeaseBreakAcknowledgmentValidator.Validate(acknowledgment);
            return acknowledgment;
        }

        /// <summary>
        /// Create an SMB2 oplock-break acknowledgment request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="oplockLevel">Lowered oplock level accepted by the client.</param>
        /// <returns>Oplock-break acknowledgment request.</returns>
        public Smb2OplockBreakAcknowledgment CreateOplockBreakAcknowledgmentRequest(ulong persistentFileId, ulong volatileFileId, Smb2OplockLevel oplockLevel)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
            {
                OplockLevel = oplockLevel,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };
            Smb2OplockBreakAcknowledgmentValidator.Validate(acknowledgment);
            return acknowledgment;
        }

        /// <summary>
        /// Apply an unsolicited SMB2 oplock-break notification to a tracked open.
        /// </summary>
        /// <param name="treeId">Tree identifier carried by the SMB2 header.</param>
        /// <param name="notification">Decoded notification payload.</param>
        /// <returns>Applied open state, previous oplock level, new oplock level, and whether an acknowledgment is required.</returns>
        public (OpenState OpenState, Smb2OplockLevel PreviousOplockLevel, Smb2OplockLevel NewOplockLevel, bool RequiresAcknowledgment) ApplyOplockBreakNotification(
            uint treeId,
            Smb2OplockBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ArgumentNullException(nameof(notification), "Notification cannot be null.");
            }

            Smb2OplockBreakNotificationValidator.Validate(notification);
            ClientOpenRecord openRecord = GetTrackedOpen(notification.PersistentFileId, notification.VolatileFileId);

            if (openRecord.TreeId != treeId)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break notification tree identifier does not match the tracked open.", nameof(treeId));
            }

            Smb2OplockLevel previousOplockLevel = openRecord.State.OplockLevel;
            bool requiresAcknowledgment;

            if (previousOplockLevel == Smb2OplockLevel.Exclusive &&
                (notification.OplockLevel == Smb2OplockLevel.None || notification.OplockLevel == Smb2OplockLevel.LevelII))
            {
                requiresAcknowledgment = true;
            }
            else if (previousOplockLevel == Smb2OplockLevel.LevelII &&
                     notification.OplockLevel == Smb2OplockLevel.None)
            {
                requiresAcknowledgment = false;
            }
            else
            {
                throw new InvalidOperationException("The unsolicited SMB2 oplock-break notification does not match the tracked client oplock state.");
            }

            openRecord.State.SetOplockLevel(notification.OplockLevel);
            return (openRecord.State, previousOplockLevel, notification.OplockLevel, requiresAcknowledgment);
        }

        /// <summary>
        /// Apply an unsolicited SMB2 lease-break notification to a tracked lease-backed open.
        /// </summary>
        /// <param name="treeId">Tree identifier carried by the SMB2 header.</param>
        /// <param name="notification">Decoded notification payload.</param>
        /// <returns>Applied open state, previous lease state, new lease state, and whether an acknowledgment is required.</returns>
        public (OpenState OpenState, Smb2LeaseState PreviousLeaseState, Smb2LeaseState NewLeaseState, bool RequiresAcknowledgment) ApplyLeaseBreakNotification(
            uint treeId,
            Smb2LeaseBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ArgumentNullException(nameof(notification), "Notification cannot be null.");
            }

            Smb2LeaseBreakNotificationValidator.Validate(notification);
            ClientOpenRecord openRecord = GetTrackedOpenByLeaseKey(treeId, notification.LeaseKey);
            Smb2LeaseState previousLeaseState = openRecord.State.LeaseState;

            if (previousLeaseState != notification.CurrentLeaseState)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification current lease state does not match the tracked open.", nameof(notification));
            }

            if ((notification.NewLeaseState & ~previousLeaseState) != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification new lease state is not a subset of the tracked open state.", nameof(notification));
            }

            openRecord.State.SetLeaseState(notification.NewLeaseState);
            return (
                openRecord.State,
                previousLeaseState,
                notification.NewLeaseState,
                (notification.Flags & Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired) != 0);
        }

        /// <summary>
        /// Apply a successful SMB2 oplock-break acknowledgment result.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server oplock-break response body.</param>
        public void ApplyOplockBreakAcknowledgmentResult(
            ulong persistentFileId,
            ulong volatileFileId,
            NtStatus status,
            Smb2OplockBreakResponse response)
        {
            ClientOpenRecord openRecord = GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.OplockBreak, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2OplockBreakResponseValidator.Validate(response);
            openRecord.State.SetOplockLevel(response.OplockLevel);
        }

        /// <summary>
        /// Apply a successful SMB2 lease-break acknowledgment result.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server lease-break response body.</param>
        public void ApplyLeaseBreakAcknowledgmentResult(
            ulong persistentFileId,
            ulong volatileFileId,
            NtStatus status,
            Smb2LeaseBreakResponse response)
        {
            ClientOpenRecord openRecord = GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.OplockBreak, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2LeaseBreakResponseValidator.Validate(response);

            if (!response.LeaseKey.AsSpan().SequenceEqual(openRecord.State.LeaseKey))
            {
                throw new ProtocolValidationException("The SMB2 lease-break response lease key does not match the tracked open.", nameof(response));
            }

            openRecord.State.SetLeaseState(response.LeaseState);
        }

        /// <summary>
        /// Create an SMB2 read request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="length">Byte count to read.</param>
        /// <param name="offset">Byte offset within the file.</param>
        /// <param name="minimumCount">Minimum byte count required for success.</param>
        /// <returns>Read request.</returns>
        public Smb2ReadRequest CreateReadRequest(ulong persistentFileId, ulong volatileFileId, uint length, ulong offset, uint minimumCount = 0)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (IsNegotiated && length > NegotiatedMaxReadSize)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "The requested SMB2 read length exceeds the negotiated maximum read size.");
            }

            Smb2ReadRequest request = new Smb2ReadRequest
            {
                Length = length,
                Offset = offset,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                MinimumCount = minimumCount,
                Channel = 0,
                RemainingBytes = 0,
                ReadChannelInfo = Array.Empty<byte>()
            };

            Smb2ReadRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 read result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server read response body.</param>
        /// <returns>Read data.</returns>
        public byte[] ApplyReadResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2ReadResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status == NtStatus.EndOfFile)
            {
                return Array.Empty<byte>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Read, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2ReadResponseValidator.Validate(response);
            return response.DataBuffer;
        }

        /// <summary>
        /// Create an SMB2 write request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="data">Data buffer to write.</param>
        /// <param name="offset">Byte offset within the file.</param>
        /// <returns>Write request.</returns>
        public Smb2WriteRequest CreateWriteRequest(ulong persistentFileId, ulong volatileFileId, byte[] data, ulong offset)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            GetTrackedOpen(persistentFileId, volatileFileId);

            if (IsNegotiated && data.Length > NegotiatedMaxWriteSize)
            {
                throw new ArgumentOutOfRangeException(nameof(data), "The SMB2 write length exceeds the negotiated maximum write size.");
            }

            Smb2WriteRequest request = new Smb2WriteRequest
            {
                Offset = offset,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Channel = 0,
                RemainingBytes = 0,
                Flags = Smb2WriteFlags.None,
                DataBuffer = (byte[])data.Clone(),
                WriteChannelInfo = Array.Empty<byte>()
            };

            Smb2WriteRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 write result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server write response body.</param>
        /// <returns>Bytes written.</returns>
        public uint ApplyWriteResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2WriteResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Write, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2WriteResponseValidator.Validate(response);
            return response.Count;
        }

        /// <summary>
        /// Create an SMB2 flush request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <returns>Flush request.</returns>
        public Smb2FlushRequest CreateFlushRequest(ulong persistentFileId, ulong volatileFileId)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2FlushRequest request = new Smb2FlushRequest
            {
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };

            Smb2FlushRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 flush result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server flush response body.</param>
        public void ApplyFlushResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2FlushResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Flush, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2FlushResponseValidator.Validate(response);
        }

        /// <summary>
        /// Create an SMB2 close request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="postQueryAttributes">Whether to request post-close attributes.</param>
        /// <returns>Close request.</returns>
        public Smb2CloseRequest CreateCloseRequest(ulong persistentFileId, ulong volatileFileId, bool postQueryAttributes = false)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2CloseRequest request = new Smb2CloseRequest
            {
                Flags = postQueryAttributes ? Smb2CloseFlags.PostQueryAttributes : Smb2CloseFlags.None,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };

            Smb2CloseRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 close result for a tracked open and remove it from the session.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server close response body.</param>
        /// <returns>Close response.</returns>
        public Smb2CloseResponse ApplyCloseResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2CloseResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Close, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2CloseResponseValidator.Validate(response);
            RemoveTrackedOpen(persistentFileId, volatileFileId);
            return response;
        }

        /// <summary>
        /// Create an SMB2 lock request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="locks">Requested byte-range lock elements.</param>
        /// <returns>Lock request.</returns>
        public Smb2LockRequest CreateLockRequest(ulong persistentFileId, ulong volatileFileId, params Smb2LockElement[] locks)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2LockRequest request = new Smb2LockRequest
            {
                LockSequence = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Locks = locks ?? throw new ArgumentNullException(nameof(locks), "Locks cannot be null.")
            };

            Smb2LockRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 lock result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server lock response body.</param>
        public void ApplyLockResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2LockResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Lock, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2LockResponseValidator.Validate(response);
        }

        /// <summary>
        /// Create an SMB2 IOCTL request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="ctlCode">FSCTL or IOCTL control code.</param>
        /// <param name="inputBuffer">Optional input buffer.</param>
        /// <param name="maxOutputResponse">Maximum accepted response output-buffer length.</param>
        /// <param name="maxInputResponse">Maximum accepted response input-buffer length.</param>
        /// <param name="flags">IOCTL flags.</param>
        /// <returns>IOCTL request.</returns>
        public Smb2IoctlRequest CreateIoctlRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            uint ctlCode,
            byte[]? inputBuffer = null,
            uint maxOutputResponse = 4096,
            uint maxInputResponse = 0,
            Smb2IoctlFlags flags = Smb2IoctlFlags.IsFsctl)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            return CreateIoctlRequestCore(
                persistentFileId,
                volatileFileId,
                ctlCode,
                inputBuffer,
                maxOutputResponse,
                maxInputResponse,
                flags);
        }

        /// <summary>
        /// Create an SMB2 IOCTL request that uses the wildcard file identifier pair.
        /// </summary>
        /// <param name="ctlCode">FSCTL or IOCTL control code.</param>
        /// <param name="inputBuffer">Optional input buffer.</param>
        /// <param name="maxOutputResponse">Maximum accepted response output-buffer length.</param>
        /// <param name="maxInputResponse">Maximum accepted response input-buffer length.</param>
        /// <param name="flags">IOCTL flags.</param>
        /// <returns>IOCTL request.</returns>
        public Smb2IoctlRequest CreateConnectionIoctlRequest(
            uint ctlCode,
            byte[]? inputBuffer = null,
            uint maxOutputResponse = 4096,
            uint maxInputResponse = 0,
            Smb2IoctlFlags flags = Smb2IoctlFlags.IsFsctl)
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before issuing SMB2 IOCTL requests.");
            }

            return CreateIoctlRequestCore(
                WildcardIoctlFileId,
                WildcardIoctlFileId,
                ctlCode,
                inputBuffer,
                maxOutputResponse,
                maxInputResponse,
                flags);
        }

        /// <summary>
        /// Apply a successful SMB2 IOCTL result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server IOCTL response body.</param>
        /// <returns>Returned output buffer.</returns>
        public byte[] ApplyIoctlResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2IoctlResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            return ApplyIoctlResultCore(status, response);
        }

        /// <summary>
        /// Apply a successful wildcard-file-id SMB2 IOCTL result.
        /// </summary>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server IOCTL response body.</param>
        /// <returns>Returned output buffer.</returns>
        public byte[] ApplyConnectionIoctlResult(NtStatus status, Smb2IoctlResponse response)
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before applying SMB2 IOCTL results.");
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            if (response.PersistentFileId != WildcardIoctlFileId || response.VolatileFileId != WildcardIoctlFileId)
            {
                throw new InvalidOperationException("The SMB2 IOCTL result does not use the wildcard file identifier pair expected for a connection-scoped request.");
            }

            return ApplyIoctlResultCore(status, response);
        }

        /// <summary>
        /// Create an SMB2 previous-version enumeration request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="maxOutputResponse">Maximum accepted snapshot-array size.</param>
        /// <returns>IOCTL request.</returns>
        public Smb2IoctlRequest CreateEnumerateSnapshotsRequest(ulong persistentFileId, ulong volatileFileId, uint maxOutputResponse = 4096)
        {
            return CreateIoctlRequest(
                persistentFileId,
                volatileFileId,
                (uint)FsctlCode.SrvEnumerateSnapshots,
                inputBuffer: Array.Empty<byte>(),
                maxOutputResponse: maxOutputResponse,
                maxInputResponse: 0,
                flags: Smb2IoctlFlags.IsFsctl);
        }

        /// <summary>
        /// Apply a successful previous-version enumeration result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server IOCTL response body.</param>
        /// <returns>Decoded snapshot array.</returns>
        public SrvSnapshotArray ApplyEnumerateSnapshotsResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2IoctlResponse response)
        {
            byte[] outputBuffer = ApplyIoctlResult(persistentFileId, volatileFileId, status, response);

            if (response.CtlCode != (uint)FsctlCode.SrvEnumerateSnapshots)
            {
                throw new InvalidOperationException("The server IOCTL result does not contain an FSCTL_SRV_ENUMERATE_SNAPSHOTS response.");
            }

            return SrvSnapshotArray.ReadFrom(outputBuffer);
        }

        /// <summary>
        /// Create an SMB2 query-info request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="informationClass">Requested file information class.</param>
        /// <param name="outputBufferLength">Maximum response buffer length.</param>
        /// <returns>Query-info request.</returns>
        public Smb2QueryInfoRequest CreateQueryInfoRequest(ulong persistentFileId, ulong volatileFileId, FileInformationClass informationClass, uint outputBufferLength = 4096)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2QueryInfoRequest request = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                OutputBufferLength = outputBufferLength,
                AdditionalInformation = 0,
                Flags = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                InputBuffer = Array.Empty<byte>()
            };

            Smb2QueryInfoRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 query-info result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server query-info response body.</param>
        /// <returns>Returned metadata buffer.</returns>
        public byte[] ApplyQueryInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2QueryInfoResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.QueryInfo, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2QueryInfoResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        /// <summary>
        /// Create an SMB2 query-directory request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="informationClass">Requested directory information class.</param>
        /// <param name="outputBufferLength">Maximum response buffer length.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="flags">Query-directory flags.</param>
        /// <returns>Query-directory request.</returns>
        public Smb2QueryDirectoryRequest CreateQueryDirectoryRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            FileInformationClass informationClass,
            uint outputBufferLength = 4096,
            string? fileNamePattern = null,
            Smb2QueryDirectoryFlags flags = Smb2QueryDirectoryFlags.None)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2QueryDirectoryRequest request = new Smb2QueryDirectoryRequest
            {
                FileInfoClass = informationClass,
                Flags = flags,
                FileIndex = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                OutputBufferLength = outputBufferLength,
                FileNamePattern = fileNamePattern ?? string.Empty
            };

            Smb2QueryDirectoryRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 query-directory result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server query-directory response body.</param>
        /// <returns>Returned directory-enumeration buffer.</returns>
        public byte[] ApplyQueryDirectoryResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2QueryDirectoryResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status == NtStatus.NoMoreFiles || status == NtStatus.NoSuchFile)
            {
                return Array.Empty<byte>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.QueryDirectory, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2QueryDirectoryResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        /// <summary>
        /// Create an SMB2 CHANGE_NOTIFY request for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="completionFilter">Requested completion-filter bits.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the directory open.</param>
        /// <param name="outputBufferLength">Maximum response-buffer length.</param>
        /// <returns>CHANGE_NOTIFY request.</returns>
        public Smb2ChangeNotifyRequest CreateChangeNotifyRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            uint outputBufferLength = 4096)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest
            {
                Flags = watchTree ? Smb2ChangeNotifyFlags.WatchTree : Smb2ChangeNotifyFlags.None,
                OutputBufferLength = outputBufferLength,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                CompletionFilter = completionFilter
            };

            Smb2ChangeNotifyRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply an SMB2 CHANGE_NOTIFY result for a tracked open.
        /// </summary>
        /// <param name="request">Original CHANGE_NOTIFY request.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server CHANGE_NOTIFY response body.</param>
        /// <returns>Decoded notify entries.</returns>
        public FileNotifyInformation[] ApplyChangeNotifyResult(Smb2ChangeNotifyRequest request, NtStatus status, Smb2ChangeNotifyResponse response)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            GetTrackedOpen(request.PersistentFileId, request.VolatileFileId);

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2ChangeNotifyRequestValidator.Validate(request);
            Smb2ChangeNotifyResponseValidator.Validate(response);

            if (status == NtStatus.NotifyEnumDir)
            {
                if (response.OutputBuffer.Length != 0)
                {
                    throw new ProtocolValidationException("STATUS_NOTIFY_ENUM_DIR responses must not carry FILE_NOTIFY_INFORMATION entries in the current slice.", nameof(response));
                }

                return Array.Empty<FileNotifyInformation>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.ChangeNotify, status);
            }

            if (request.OutputBufferLength != 0 && response.OutputBuffer.Length > request.OutputBufferLength)
            {
                throw new ProtocolValidationException("The CHANGE_NOTIFY response output buffer exceeds the request limit.", nameof(response));
            }

            if (response.OutputBuffer.Length == 0)
            {
                throw new ProtocolValidationException("Successful CHANGE_NOTIFY responses must carry at least one FILE_NOTIFY_INFORMATION entry.", nameof(response));
            }

            FileNotifyInformation[] entries = FileNotifyInformation.DecodeEntries(response.OutputBuffer);
            bool watchTree = (request.Flags & Smb2ChangeNotifyFlags.WatchTree) != 0;

            for (int index = 0; index < entries.Length; index++)
            {
                string fileName = entries[index].FileName;

                if (fileName.Length == 0)
                {
                    throw new ProtocolValidationException("CHANGE_NOTIFY response entries must carry a relative path.", nameof(response));
                }

                if (fileName[0] == '\\' || fileName[0] == '/')
                {
                    throw new ProtocolValidationException("CHANGE_NOTIFY response entries must be relative to the watched directory.", nameof(response));
                }

                if (fileName.IndexOf('\"') >= 0)
                {
                    throw new ProtocolValidationException("CHANGE_NOTIFY response entries must not contain quote characters.", nameof(response));
                }

                if (!watchTree && (fileName.IndexOf('\\') >= 0 || fileName.IndexOf('/') >= 0))
                {
                    throw new ProtocolValidationException("Non-recursive CHANGE_NOTIFY responses must not contain nested relative paths.", nameof(response));
                }
            }

            return entries;
        }

        /// <summary>
        /// Create an SMB2 set-info request that applies FILE_BASIC_INFORMATION to a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="information">Basic information payload.</param>
        /// <returns>Set-info request.</returns>
        public Smb2SetInfoRequest CreateSetBasicInfoRequest(ulong persistentFileId, ulong volatileFileId, FileBasicInformation information)
        {
            if (information == null)
            {
                throw new ArgumentNullException(nameof(information), "Information cannot be null.");
            }

            return CreateSetInfoRequest(persistentFileId, volatileFileId, FileInformationClass.BasicInformation, information.ToByteArray());
        }

        /// <summary>
        /// Create an SMB2 set-info request that applies FILE_END_OF_FILE_INFORMATION to a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="endOfFile">Requested end-of-file size.</param>
        /// <returns>Set-info request.</returns>
        public Smb2SetInfoRequest CreateSetEndOfFileInfoRequest(ulong persistentFileId, ulong volatileFileId, ulong endOfFile)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.EndOfFileInformation,
                new FileEndOfFileInformation
                {
                    EndOfFile = endOfFile
                }.ToByteArray());
        }

        /// <summary>
        /// Create an SMB2 set-info request that applies FILE_ALLOCATION_INFORMATION to a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="allocationSize">Requested allocation size.</param>
        /// <returns>Set-info request.</returns>
        public Smb2SetInfoRequest CreateSetAllocationInfoRequest(ulong persistentFileId, ulong volatileFileId, ulong allocationSize)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.AllocationInformation,
                new FileAllocationInformation
                {
                    AllocationSize = allocationSize
                }.ToByteArray());
        }

        /// <summary>
        /// Create an SMB2 set-info request that applies FILE_DISPOSITION_INFORMATION to a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="deletePending">Requested delete-pending state.</param>
        /// <returns>Set-info request.</returns>
        public Smb2SetInfoRequest CreateSetDispositionInfoRequest(ulong persistentFileId, ulong volatileFileId, bool deletePending)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.DispositionInformation,
                new FileDispositionInformation
                {
                    DeletePending = deletePending
                }.ToByteArray());
        }

        /// <summary>
        /// Create an SMB2 set-info request that applies FILE_RENAME_INFORMATION_TYPE_2 to a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="path">New relative path within the tree.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <returns>Set-info request.</returns>
        public Smb2SetInfoRequest CreateSetRenameInfoRequest(ulong persistentFileId, ulong volatileFileId, string path, bool replaceIfExists = false)
        {
            string normalizedPath = NormalizeOpenPath(path);
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.RenameInformation,
                new FileRenameInformationType2
                {
                    ReplaceIfExists = replaceIfExists,
                    RootDirectory = 0,
                    FileName = normalizedPath
                }.ToByteArray());
        }

        /// <summary>
        /// Apply an SMB2 set-info result for a tracked open.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server set-info response body.</param>
        public void ApplySetInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response)
        {
            GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.SetInfo, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2SetInfoResponseValidator.Validate(response);
        }

        /// <summary>
        /// Apply a successful FILE_DISPOSITION_INFORMATION result to the tracked open state.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server set-info response body.</param>
        /// <param name="deletePending">Applied delete-pending state.</param>
        public void ApplySetDispositionInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response, bool deletePending)
        {
            ClientOpenRecord openRecord = GetTrackedOpen(persistentFileId, volatileFileId);
            ApplySetInfoResult(persistentFileId, volatileFileId, status, response);
            openRecord.State.SetDeletePending(deletePending);
        }

        /// <summary>
        /// Apply a successful FILE_RENAME_INFORMATION result to the tracked open state.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server set-info response body.</param>
        /// <param name="path">Applied new relative path.</param>
        public void ApplySetRenameInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response, string path)
        {
            ClientOpenRecord openRecord = GetTrackedOpen(persistentFileId, volatileFileId);
            ApplySetInfoResult(persistentFileId, volatileFileId, status, response);
            openRecord.State.UpdatePath(NormalizeOpenPath(path));
        }

        /// <summary>
        /// Create an SMB2 tree-disconnect request for a connected tree.
        /// </summary>
        /// <param name="treeId">Tree identifier.</param>
        /// <returns>Tree-disconnect request.</returns>
        public Smb2TreeDisconnectRequest CreateTreeDisconnectRequest(uint treeId)
        {
            if (!_Trees.ContainsKey(treeId))
            {
                throw new InvalidOperationException("The specified tree identifier is not connected on this client session.");
            }

            Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest();
            Smb2TreeDisconnectRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply a successful SMB2 tree-disconnect result.
        /// </summary>
        /// <param name="treeId">Tree identifier.</param>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server tree-disconnect response body.</param>
        public void ApplyTreeDisconnectResult(uint treeId, NtStatus status, Smb2TreeDisconnectResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.TreeDisconnect, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2TreeDisconnectResponseValidator.Validate(response);
            RemoveOpensForTree(treeId);

            if (_Trees.TryGetValue(treeId, out TreeConnectState? treeState))
            {
                treeState.Disconnect();
                treeState.Dispose();
                _Trees.Remove(treeId);
            }
        }

        /// <summary>
        /// Create an SMB2 logoff request for the authenticated session.
        /// </summary>
        /// <returns>Logoff request.</returns>
        public Smb2LogoffRequest CreateLogoffRequest()
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before logoff.");
            }

            Smb2LogoffRequest request = new Smb2LogoffRequest();
            Smb2LogoffRequestValidator.Validate(request);
            return request;
        }

        /// <summary>
        /// Apply a successful SMB2 logoff result.
        /// </summary>
        /// <param name="status">NTSTATUS from the server response.</param>
        /// <param name="response">Server logoff response body.</param>
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
            ResetAuthenticatedState();
        }

        private ulong DequeueMessageIdRange(int creditsToConsume)
        {
            ulong messageId = _AvailableMessageIds.Dequeue();
            ulong expectedMessageId = messageId;

            for (int index = 1; index < creditsToConsume; index++)
            {
                expectedMessageId++;
                ulong consumedMessageId = _AvailableMessageIds.Dequeue();

                if (consumedMessageId != expectedMessageId)
                {
                    throw new InvalidOperationException("The local SMB2 message identifier window is not contiguous enough for the requested credit charge.");
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

            if (NegotiatedDialect == null || NegotiatedDialect.Value < SmbDialect.Smb21)
            {
                if (creditCharge > 1)
                {
                    throw new InvalidOperationException("Only bounded SMB 2.1 large read and write requests may consume multiple SMB2 credits.");
                }

                return;
            }

            if (command != Smb2Command.Read && command != Smb2Command.Write && creditCharge > 1)
            {
                throw new InvalidOperationException("Only bounded SMB 2.1 read and write requests may carry a multi-credit SMB2 charge.");
            }
        }

        private void GrantCredits(ushort creditCount)
        {
            _ConnectionState.Credits.Grant(creditCount);

            for (ushort index = 0; index < creditCount; index++)
            {
                _AvailableMessageIds.Enqueue(_NextMessageIdToGrant);
                _NextMessageIdToGrant++;
            }
        }

        private RequestState GetPendingRequest(ulong messageId)
        {
            if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState))
            {
                throw new ProtocolValidationException("The SMB2 response does not match any pending request on this client session.", nameof(messageId));
            }

            return requestState;
        }

        private void EnsureConnectedTree(uint treeId)
        {
            if (!IsAuthenticated || SessionId == null)
            {
                throw new InvalidOperationException("An authenticated session is required before file operations.");
            }

            if (!_Trees.ContainsKey(treeId))
            {
                throw new InvalidOperationException("The specified tree identifier is not connected on this client session.");
            }
        }

        private ClientOpenRecord GetTrackedOpen(ulong persistentFileId, ulong volatileFileId)
        {
            if (!_Opens.TryGetValue(volatileFileId, out ClientOpenRecord? openRecord) ||
                openRecord.State.PersistentFileId != persistentFileId)
            {
                throw new InvalidOperationException("The specified file identifier is not open on this client session.");
            }

            return openRecord;
        }

        private ClientOpenRecord GetTrackedOpenByLeaseKey(uint treeId, byte[] leaseKey)
        {
            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            foreach (ClientOpenRecord openRecord in _Opens.Values)
            {
                if (openRecord.TreeId == treeId &&
                    openRecord.State.LeaseKey.AsSpan().SequenceEqual(leaseKey))
                {
                    return openRecord;
                }
            }

            throw new InvalidOperationException("The specified lease key is not tracked on this client session.");
        }

        private Smb2SetInfoRequest CreateSetInfoRequest(ulong persistentFileId, ulong volatileFileId, FileInformationClass informationClass, byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer), "Buffer cannot be null.");
            }

            GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2SetInfoRequest request = new Smb2SetInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                AdditionalInformation = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Buffer = (byte[])buffer.Clone()
            };

            Smb2SetInfoRequestValidator.Validate(request);
            return request;
        }

        private Smb2IoctlRequest CreateIoctlRequestCore(
            ulong persistentFileId,
            ulong volatileFileId,
            uint ctlCode,
            byte[]? inputBuffer,
            uint maxOutputResponse,
            uint maxInputResponse,
            Smb2IoctlFlags flags)
        {
            Smb2IoctlRequest request = new Smb2IoctlRequest
            {
                CtlCode = ctlCode,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                MaxInputResponse = maxInputResponse,
                MaxOutputResponse = maxOutputResponse,
                Flags = flags,
                InputBuffer = inputBuffer == null ? Array.Empty<byte>() : (byte[])inputBuffer.Clone()
            };

            Smb2IoctlRequestValidator.Validate(request);
            return request;
        }

        private static byte[] ApplyIoctlResultCore(NtStatus status, Smb2IoctlResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Ioctl, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2IoctlResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        private void RemoveTrackedOpen(ulong persistentFileId, ulong volatileFileId)
        {
            if (_Opens.TryGetValue(volatileFileId, out ClientOpenRecord? openRecord) &&
                openRecord.State.PersistentFileId == persistentFileId)
            {
                openRecord.State.Dispose();
                _Opens.Remove(volatileFileId);
            }
        }

        private void ValidateBreakNotificationPacket(Smb2CompoundPacket responsePacket, ReadOnlyMemory<byte> packetBytes, ushort expectedStructureSize, string notificationName)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            if (responsePacket.Entries.Count != 1)
            {
                throw new ProtocolValidationException("The managed client break-notification path expects a single SMB2 packet entry.", nameof(responsePacket));
            }

            Smb2CompoundPacketEntry entry = responsePacket.Entries[0];
            Smb2Header responseHeader = entry.Header;

            if (responseHeader.Command != Smb2Command.OplockBreak || responseHeader.MessageId != UInt64.MaxValue)
            {
                throw new ProtocolValidationException("The packet is not an unsolicited SMB2 " + notificationName + " notification.", nameof(responsePacket));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.ServerToRedir) == 0)
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification must set the ServerToRedir flag.", nameof(responsePacket));
            }

            if ((responseHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification must not set the AsyncCommand flag.", nameof(responsePacket));
            }

            if (SessionId == null || responseHeader.SessionId != SessionId.Value)
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification session identifier is invalid.", nameof(responsePacket));
            }

            byte[] payload = entry.Payload;

            if (payload.Length < 2)
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification payload is truncated.", nameof(responsePacket));
            }

            LittleEndianReader payloadReader = new LittleEndianReader(payload);

            if (payloadReader.ReadUInt16() != expectedStructureSize)
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification structure size is invalid.", nameof(responsePacket));
            }

            bool mustBeSigned = IsAuthenticated && IsSigningRequired;

            if ((responseHeader.Flags & Smb2HeaderFlags.Signed) == 0)
            {
                if (mustBeSigned)
                {
                    throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification omitted the required Signed flag.", nameof(responsePacket));
                }

                return;
            }

            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
            byte[] signingKey = GetSessionSigningKey(responseHeader.SessionId);
            byte[] expectedMessage = packetBytes.ToArray();
            Array.Clear(expectedMessage, Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);

            if (!signer.Verify(expectedMessage, signingKey, ReadOnlySpan<byte>.Empty, responseHeader.Signature))
            {
                throw new ProtocolValidationException("The unsolicited SMB2 " + notificationName + " notification signature did not verify.", nameof(responsePacket));
            }
        }

        private static byte[] CreateLeaseKey(byte[]? leaseKey)
        {
            if (leaseKey == null)
            {
                return RandomNumberGenerator.GetBytes(16);
            }

            if (leaseKey.Length != 16)
            {
                throw new ArgumentException("The SMB 2.1 lease key must be 16 bytes long.", nameof(leaseKey));
            }

            return (byte[])leaseKey.Clone();
        }

        private void RemoveOpensForTree(uint treeId)
        {
            List<ulong> volatileFileIds = new List<ulong>();

            foreach (KeyValuePair<ulong, ClientOpenRecord> entry in _Opens)
            {
                if (entry.Value.TreeId == treeId)
                {
                    volatileFileIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                ulong volatileFileId = volatileFileIds[index];
                ClientOpenRecord openRecord = _Opens[volatileFileId];
                openRecord.State.Dispose();
                _Opens.Remove(volatileFileId);
            }
        }

        private void ResetAuthenticatedState()
        {
            foreach (KeyValuePair<ulong, ClientOpenRecord> entry in _Opens)
            {
                entry.Value.State.Dispose();
            }

            _Opens.Clear();

            foreach (TreeConnectState treeState in _Trees.Values)
            {
                if (treeState.IsConnected)
                {
                    treeState.Disconnect();
                }

                treeState.Dispose();
            }

            _Trees.Clear();
            _SessionState.Dispose();
            _SessionState = new SessionState();
            _SessionBaseKey = null;
            _SessionSigningKey = null;
            _StandardNegotiateMessage = null;
            SessionId = null;
        }

        private bool ShouldSignCommand(Smb2Command command, ulong sessionId)
        {
            return IsSigningRequired &&
                _SessionState.IsAuthenticated &&
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
            return IsSigningRequired &&
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
                throw new InvalidOperationException("A non-zero session identifier is required before SMB2 signing keys can be used.");
            }

            if (_SessionSigningKey == null || _SessionSigningKey.Length == 0)
            {
                throw new InvalidOperationException("The client does not have a signing key for the authenticated SMB2 session.");
            }

            if (!_SessionState.IsAuthenticated || SessionId != sessionId)
            {
                throw new InvalidOperationException("The client does not have an authenticated SMB2 session for the supplied signing key request.");
            }

            return _SessionSigningKey;
        }

        private static NtlmNegotiateMessage CreateStandardNegotiateMessage(OpenCifsClientCredential credential)
        {
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

        private static NtlmV2ClientChallenge CreateStandardClientChallenge(NtlmChallengeMessage challengeMessage)
        {
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

        private static NtlmNegotiateFlags DetermineStandardAuthenticateFlags(NtlmNegotiateFlags challengeFlags)
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

        private static bool TryExtractStandardChallengeToken(ReadOnlyMemory<byte> securityBuffer, out byte[]? challengeTokenBytes, out bool wrapAuthenticateInSpnego)
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

        private static string NormalizeOpenPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\').Trim('\\');

            if (normalizedPath.Length == 0)
            {
                throw new InvalidOperationException("The file path must resolve to a non-empty relative path.");
            }

            return normalizedPath;
        }

        private static byte[] CreateRandomBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
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

        private sealed class ClientOpenRecord
        {
            public uint TreeId { get; set; }

            public OpenState State { get; set; } = null!;
        }
    }
}

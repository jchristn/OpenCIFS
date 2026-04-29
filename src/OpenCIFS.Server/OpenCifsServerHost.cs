namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Enumeration;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using SystemFileAttributes = System.IO.FileAttributes;

    /// <summary>
        /// In-memory server host for the currently implemented SMB 2.1-or-earlier negotiate, session, tree, and file-I/O slices.
    /// </summary>
    public sealed class OpenCifsServerHost
    {
        private const int Smb2HeaderSignatureOffset = 48;
        private const int Smb2HeaderSignatureLength = 16;
        private const uint GenericRead = 0x80000000U;
        private const uint GenericWrite = 0x40000000U;
        private const uint DeleteAccess = 0x00010000U;
        private const uint FileReadData = 0x00000001U;
        private const uint FileWriteData = 0x00000002U;
        private const uint FileAppendData = 0x00000004U;
        private const uint FileReadAttributes = 0x00000080U;
        private const uint FileWriteAttributes = 0x00000100U;
        private const uint FileShareRead = 0x00000001U;
        private const uint FileShareWrite = 0x00000002U;
        private const uint FileShareDelete = 0x00000004U;
        private const uint ImplementedMaxTransactSize = 65536;
        private const uint ImplementedMaxReadWriteSize = Smb2CreditChargeHelper.ImplementedLargeReadWriteSize;
        private const ulong WildcardIoctlFileId = UInt64.MaxValue;
        private const ulong StickyDisableFileTimeDirective = UInt64.MaxValue;
        private const ulong StickyEnableFileTimeDirective = UInt64.MaxValue - 1;
        private const uint FileSystemBytesPerSector = 512;
        private const uint FileSystemSectorsPerAllocationUnit = 8;
        private const int FileSystemMaximumComponentNameLength = 255;
        private const string DefaultFileSystemName = "NTFS";

        private readonly Dictionary<string, OpenCifsServerAccount> _Accounts = new Dictionary<string, OpenCifsServerAccount>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<ulong> _AvailableMessageIds = new HashSet<ulong>();
        private readonly CreditState _Credits = new CreditState();
        private readonly Dictionary<ulong, RequestState> _PendingRequests = new Dictionary<ulong, RequestState>();
        private readonly Dictionary<ulong, PendingChangeNotifySubscription> _PendingChangeNotifySubscriptions = new Dictionary<ulong, PendingChangeNotifySubscription>();
        private readonly ConcurrentQueue<OpenCifsServerAsyncResponse> _ReadyAsyncResponses = new ConcurrentQueue<OpenCifsServerAsyncResponse>();
        private readonly Dictionary<string, RegisteredShareRecord> _RegisteredShares = new Dictionary<string, RegisteredShareRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<ulong, ServerSessionRecord> _Sessions = new Dictionary<ulong, ServerSessionRecord>();
        private readonly Dictionary<string, ulong> _DeclaredAllocationSizes = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, TrackedFileTimestamps> _TrackedFileTimestamps = new Dictionary<string, TrackedFileTimestamps>(StringComparer.OrdinalIgnoreCase);
        private readonly OpenCifsServerSharedState _SharedState;
        private readonly SemaphoreSlim _AsyncResponseSignal = new SemaphoreSlim(0);
        private readonly ulong _ServerStartTime;
        private readonly Guid _HostId = Guid.NewGuid();
        private Guid _NegotiatedClientGuid = Guid.Empty;
        private Smb2GlobalCapabilities _NegotiatedClientCapabilities = Smb2GlobalCapabilities.None;
        private Smb2SecurityMode _NegotiatedClientSecurityMode = Smb2SecurityMode.SigningEnabled;
        private Smb2SecurityMode _NegotiatedServerSecurityMode = Smb2SecurityMode.SigningEnabled;
        private Smb2GlobalCapabilities _NegotiatedServerCapabilities = Smb2GlobalCapabilities.None;
        private SmbDialect[] _NegotiatedClientDialects = Array.Empty<SmbDialect>();
        private SmbDialect? _NegotiatedDialect;
        private ulong _NextMessageIdToGrant = 1;
        private ulong _NextSessionId = 1;
        private uint _NextTreeId = 1;
        private ulong _NextAsyncId = 1;
        private ulong _NextChangeNotifySequenceId = 1;

        /// <summary>
        /// Initialize a server host.
        /// </summary>
        /// <param name="options">Server options.</param>
        /// <param name="sharedState">Optional shared server-wide state for multi-connection direct-TCP hosts.</param>
        public OpenCifsServerHost(OpenCifsServerOptions options, OpenCifsServerSharedState? sharedState = null)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            Options.Validate();
            _SharedState = sharedState ?? new OpenCifsServerSharedState();
            ServerGuid = Guid.NewGuid();
            _ServerStartTime = ToFileTimeUtc(DateTimeOffset.UtcNow);
            _AvailableMessageIds.Add(0);
            _Credits.Grant(1);
            _SharedState.RegisterHost(this);
        }

        /// <summary>
        /// Server options.
        /// </summary>
        public OpenCifsServerOptions Options { get; }

        /// <summary>
        /// Server GUID advertised during negotiation.
        /// </summary>
        public Guid ServerGuid { get; }

        /// <summary>
        /// Currently available SMB2 request credits on the active connection model.
        /// </summary>
        public int AvailableCredits
        {
            get
            {
                return _Credits.AvailableCredits;
            }
        }

        /// <summary>
        /// Register an in-memory account for the current host instance.
        /// </summary>
        /// <param name="account">Account definition.</param>
        public void RegisterAccount(OpenCifsServerAccount account)
        {
            if (account == null)
            {
                throw new ArgumentNullException(nameof(account), "Account cannot be null.");
            }

            OpenCifsServerAccount clonedAccount = new OpenCifsServerAccount
            {
                UserName = account.UserName,
                UserDomain = account.UserDomain,
                Password = account.Password
            };
            _Accounts[GetAccountKey(clonedAccount.UserName, clonedAccount.UserDomain)] = clonedAccount;
        }

        /// <summary>
        /// Register a share backend for the current host instance.
        /// </summary>
        /// <param name="share">Share definition.</param>
        public void RegisterShare(OpenCifsServerShareBackend share)
        {
            if (share == null)
            {
                throw new ArgumentNullException(nameof(share), "Share cannot be null.");
            }

            RegisteredShareRecord shareRecord = NormalizeRegisteredShare(share);

            if (_RegisteredShares.ContainsKey(shareRecord.ShareName))
            {
                throw new InvalidOperationException("A filesystem-backed share with the same name is already registered.");
            }

            _RegisteredShares.Add(shareRecord.ShareName, shareRecord);
        }

        /// <summary>
        /// Register a local filesystem-backed share for the current host instance.
        /// </summary>
        /// <param name="share">Share definition.</param>
        public void RegisterShare(OpenCifsServerFileSystemShare share)
        {
            RegisterShare((OpenCifsServerShareBackend)share);
        }

        /// <summary>
        /// Try to dequeue a final asynchronous SMB2 response emitted by a pending async request.
        /// </summary>
        /// <param name="response">Dequeued response when one is available.</param>
        /// <returns><c>true</c> when a response was dequeued; otherwise <c>false</c>.</returns>
        public bool TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? response)
        {
            if (!_ReadyAsyncResponses.TryDequeue(out response))
            {
                return false;
            }

            return true;
        }

        internal Task WaitForAsyncResponseAsync(CancellationToken cancellationToken)
        {
            if (!_ReadyAsyncResponses.IsEmpty)
            {
                return Task.CompletedTask;
            }

            return _AsyncResponseSignal.WaitAsync(cancellationToken);
        }

        internal object SyncRoot
        {
            get
            {
                return _SharedState.SyncRoot;
            }
        }

        internal void UnregisterFromSharedState()
        {
            _SharedState.UnregisterHost(this);
        }

        internal void HandleTransportDisconnect()
        {
            List<ServerSessionRecord> sessionRecords = new List<ServerSessionRecord>(_Sessions.Values);

            for (int index = 0; index < sessionRecords.Count; index++)
            {
                CleanupDisconnectedSessionRecord(sessionRecords[index]);
            }

            _Sessions.Clear();
            _PendingRequests.Clear();
            _PendingChangeNotifySubscriptions.Clear();

            while (_ReadyAsyncResponses.TryDequeue(out _))
            {
            }
        }

        private void EnqueueAsyncResponse(OpenCifsServerAsyncResponse response)
        {
            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            _ReadyAsyncResponses.Enqueue(response);
            _AsyncResponseSignal.Release();
        }

        private void CleanupDisconnectedSessionRecord(ServerSessionRecord sessionRecord)
        {
            List<ulong> volatileFileIds = new List<ulong>(sessionRecord.Opens.Keys);

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                ulong volatileFileId = volatileFileIds[index];

                if (sessionRecord.Opens.TryGetValue(volatileFileId, out ServerOpenRecord? openRecord) &&
                    openRecord != null &&
                    CanDetachDurableOpen(openRecord))
                {
                    DetachDurableOpenRecord(sessionRecord, volatileFileId, openRecord);
                    continue;
                }

                CloseOpenRecord(sessionRecord, volatileFileId);
            }

            foreach (ServerTreeRecord treeRecord in sessionRecord.Trees.Values)
            {
                treeRecord.State.Dispose();
            }

            sessionRecord.Trees.Clear();
            sessionRecord.State.Dispose();
        }

        private void DetachDurableOpenRecord(ServerSessionRecord sessionRecord, ulong volatileFileId, ServerOpenRecord openRecord)
        {
            OpenCifsServerDurableOpenRecord durableOpenRecord = new OpenCifsServerDurableOpenRecord
            {
                PersistentFileId = openRecord.State.PersistentFileId,
                DurableOwnerUserName = sessionRecord.UserName,
                DurableOwnerUserDomain = sessionRecord.UserDomain,
                ShareName = openRecord.ShareName,
                ShareRootPath = openRecord.ShareRootPath,
                Backend = openRecord.Backend,
                FullPath = openRecord.FullPath,
                RelativePath = openRecord.State.Path,
                DesiredAccess = openRecord.DesiredAccess,
                ShareAccess = openRecord.ShareAccess,
                CanRead = openRecord.CanRead,
                CanWrite = openRecord.CanWrite,
                CanReadData = openRecord.CanReadData,
                CanWriteData = openRecord.CanWriteData,
                CanDelete = openRecord.CanDelete,
                GrantedOplockLevel = openRecord.GrantedOplockLevel,
                IsDeletePending = openRecord.State.IsDeletePending,
                SuppressAccessTimeUpdates = openRecord.SuppressAccessTimeUpdates,
                SuppressModificationTimeUpdates = openRecord.SuppressModificationTimeUpdates,
                SuppressChangeTimeUpdates = openRecord.SuppressChangeTimeUpdates,
                Stream = openRecord.Stream
            };

            for (int index = 0; index < openRecord.Locks.Count; index++)
            {
                ServerByteRangeLock byteRangeLock = openRecord.Locks[index];
                durableOpenRecord.Locks.Add(new OpenCifsServerDetachedByteRangeLock
                {
                    Offset = byteRangeLock.Offset,
                    Length = byteRangeLock.Length,
                    IsShared = byteRangeLock.IsShared
                });
            }

            openRecord.Stream = null;
            openRecord.State.Dispose();
            sessionRecord.Opens.Remove(volatileFileId);
            _SharedState.PutDetachedDurableOpen(durableOpenRecord);
        }

        private static bool CanDetachDurableOpen(ServerOpenRecord openRecord)
        {
            return openRecord.State.IsDurable &&
                !openRecord.IsDirectory &&
                !openRecord.IsOplockBreakInProgress;
        }

        /// <summary>
        /// Get the dialects currently advertised by this host.
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
        /// Validate an inbound SMB2 request header against the current SMB 2.0.2 credit window and reserve its message identifier.
        /// </summary>
        /// <param name="requestHeader">Request header to validate.</param>
        /// <param name="expectedCommand">Expected command for the paired request body.</param>
        /// <param name="expectedSessionId">Expected session identifier in the request header.</param>
        /// <param name="expectedTreeId">Expected tree identifier in the request header.</param>
        /// <param name="allowedRequestFlags">Additional request flags allowed for the current validation path.</param>
        public void ValidateAndAcceptRequestHeader(Smb2Header requestHeader, Smb2Command expectedCommand, ulong expectedSessionId = 0, uint expectedTreeId = 0, Smb2HeaderFlags allowedRequestFlags = Smb2HeaderFlags.None)
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

            Smb2HeaderFlags unsupportedFlags = requestHeader.Flags & ~(allowedRequestFlags | Smb2HeaderFlags.Signed);

            if (unsupportedFlags != Smb2HeaderFlags.None)
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

        /// <summary>
        /// Create an SMB2 response header for a previously accepted request and grant credits back to the client.
        /// </summary>
        /// <param name="requestHeader">Accepted request header.</param>
        /// <param name="status">Response status.</param>
        /// <param name="sessionId">Response session identifier override when the response assigns a new session.</param>
        /// <param name="treeId">Response tree identifier override when the response assigns a new tree.</param>
        /// <param name="additionalFlags">Additional SMB2 response flags to set on the generated header.</param>
        /// <returns>Response header.</returns>
        public Smb2Header CreateResponseHeader(Smb2Header requestHeader, NtStatus status, ulong sessionId = 0, uint treeId = 0, Smb2HeaderFlags additionalFlags = Smb2HeaderFlags.None)
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
                _PendingChangeNotifySubscriptions.Remove(requestHeader.MessageId);

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
                    SessionId = sessionId != 0 ? sessionId : requestHeader.SessionId,
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
                SessionId = sessionId != 0 ? sessionId : requestHeader.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(responseHeader);
            return responseHeader;
        }

        /// <summary>
        /// Serialize a response packet and sign any entries that carry the SMB2 Signed flag for an authenticated session with negotiated SMB 2.x key material.
        /// </summary>
        /// <param name="responsePacket">Response packet to serialize.</param>
        /// <returns>Serialized packet bytes with any applicable SMB2 signatures applied.</returns>
        public byte[] FinalizeResponsePacket(Smb2CompoundPacket responsePacket)
        {
            if (responsePacket == null)
            {
                throw new ArgumentNullException(nameof(responsePacket), "ResponsePacket cannot be null.");
            }

            byte[] packetBytes = responsePacket.ToByteArray();
            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
            int offset = 0;

            for (int index = 0; index < responsePacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[index];
                int entryLength = responseEntry.Header.NextCommand == 0
                    ? packetBytes.Length - offset
                    : checked((int)responseEntry.Header.NextCommand);

                if ((responseEntry.Header.Flags & Smb2HeaderFlags.Signed) != 0 &&
                    TryGetSessionSigningKey(responseEntry.Header.SessionId, out byte[]? signingKey) &&
                    signingKey != null)
                {
                    Array.Clear(packetBytes, offset + Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);
                    byte[] signature = signer.Sign(packetBytes.AsSpan(offset, entryLength), signingKey, ReadOnlySpan<byte>.Empty);
                    Buffer.BlockCopy(signature, 0, packetBytes, offset + Smb2HeaderSignatureOffset, signature.Length);
                }

                offset += entryLength;
            }

            return packetBytes;
        }

        /// <summary>
        /// Validate SMB2 request signatures for a serialized packet against the current server session state.
        /// </summary>
        /// <param name="requestPacket">Parsed SMB2 request packet.</param>
        /// <param name="packetBytes">Serialized SMB2 request bytes.</param>
        public void ValidateRequestPacket(Smb2CompoundPacket requestPacket, ReadOnlyMemory<byte> packetBytes)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
            int offset = 0;

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[index];
                Smb2Header requestHeader = requestEntry.Header;
                int entryLength = requestHeader.NextCommand == 0
                    ? packetBytes.Length - offset
                    : checked((int)requestHeader.NextCommand);
                bool requestMustBeSigned = ShouldRequireSignedRequest(requestHeader, out byte[]? signingKey);

                if (requestHeader.Command == Smb2Command.Negotiate && (requestHeader.Flags & Smb2HeaderFlags.Signed) != 0)
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

                if (signingKey == null || signingKey.Length == 0)
                {
                    throw new ProtocolValidationException("The server does not have a signing key for the signed SMB2 request.", nameof(requestPacket));
                }

                byte[] expectedMessage = packetBytes.Slice(offset, entryLength).ToArray();
                Array.Clear(expectedMessage, Smb2HeaderSignatureOffset, Smb2HeaderSignatureLength);

                if (!signer.Verify(expectedMessage, signingKey, ReadOnlySpan<byte>.Empty, requestHeader.Signature))
                {
                    throw new ProtocolValidationException("The SMB2 request signature did not verify.", nameof(requestPacket));
                }

                offset += entryLength;
            }
        }

        /// <summary>
        /// Handle an SMB2 cancel request against the current pending-request table.
        /// </summary>
        /// <param name="requestHeader">SMB2 cancel request header.</param>
        /// <param name="request">Cancel request body.</param>
        /// <returns>Cancellation result. SMB2 cancel requests do not receive direct responses; any returned header or payload targets the cancelled request.</returns>
        public OpenCifsServerCancelResult HandleCancel(Smb2Header requestHeader, Smb2CancelRequest request)
        {
            ValidateCancelRequestHeader(requestHeader);
            Smb2CancelRequestValidator.Validate(request);

            OpenCifsServerCancelResult result = new OpenCifsServerCancelResult();

            if ((requestHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0)
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
                _PendingChangeNotifySubscriptions.Remove(asyncTargetHeader.MessageId);
                Smb2ErrorResponse cancelledErrorResponse = new Smb2ErrorResponse();
                Smb2ErrorResponseValidator.Validate(cancelledErrorResponse);
                result.TargetResponseHeader = CreateResponseHeader(asyncTargetHeader, NtStatus.Cancelled, sessionId: asyncTargetHeader.SessionId, treeId: asyncTargetHeader.TreeId);
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

            if (!TryCreateDefaultResponsePayload(targetHeader.Command, out byte[]? payload) || payload == null)
            {
                return result;
            }

            requestState.Cancel();
            result.TargetResponseHeader = CreateResponseHeader(targetHeader, NtStatus.Cancelled, sessionId: targetHeader.SessionId, treeId: targetHeader.TreeId);
            result.TargetResponsePayload = payload;
            result.WasCancelled = true;
            return result;
        }

        /// <summary>
        /// Handle an SMB2 CHANGE_NOTIFY request through the header-wrapped async path.
        /// </summary>
        /// <param name="requestHeader">SMB2 request header.</param>
        /// <param name="request">CHANGE_NOTIFY request body.</param>
        /// <returns>Immediate response, either an interim async pending response or a final error response.</returns>
        public OpenCifsServerAsyncResponse HandleChangeNotify(Smb2Header requestHeader, Smb2ChangeNotifyRequest request)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            Smb2ChangeNotifyRequestValidator.Validate(request);
            ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.ChangeNotify, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);

            if (!TryGetAuthenticatedTree(requestHeader.SessionId, requestHeader.TreeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateChangeNotifyErrorResponse(requestHeader, NtStatus.AccessDenied, requestHeader.SessionId, requestHeader.TreeId);
            }

            if (!TryGetOpen(sessionRecord, requestHeader.TreeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateChangeNotifyErrorResponse(requestHeader, NtStatus.FileClosed, requestHeader.SessionId, requestHeader.TreeId);
            }

            if (!openRecord.IsDirectory)
            {
                return CreateChangeNotifyErrorResponse(requestHeader, NtStatus.InvalidParameter, requestHeader.SessionId, requestHeader.TreeId);
            }

            if (!CanListDirectory(openRecord.DesiredAccess))
            {
                return CreateChangeNotifyErrorResponse(requestHeader, NtStatus.AccessDenied, requestHeader.SessionId, requestHeader.TreeId);
            }

            Smb2Header interimHeader = CreateInterimAsyncResponseHeader(requestHeader);
            _PendingChangeNotifySubscriptions[requestHeader.MessageId] = new PendingChangeNotifySubscription
            {
                SequenceId = _NextChangeNotifySequenceId++,
                MessageId = requestHeader.MessageId,
                SessionId = requestHeader.SessionId,
                TreeId = requestHeader.TreeId,
                PersistentFileId = request.PersistentFileId,
                VolatileFileId = request.VolatileFileId,
                DirectoryFullPath = openRecord.FullPath,
                WatchTree = (request.Flags & Smb2ChangeNotifyFlags.WatchTree) != 0,
                CompletionFilter = request.CompletionFilter,
                OutputBufferLength = request.OutputBufferLength
            };

            Smb2ErrorResponse interimErrorResponse = new Smb2ErrorResponse();
            Smb2ErrorResponseValidator.Validate(interimErrorResponse);
            return new OpenCifsServerAsyncResponse
            {
                Header = interimHeader,
                Payload = interimErrorResponse.ToByteArray()
            };
        }

        /// <summary>
        /// Handle an SMB2 compounded request packet for the currently implemented unrelated-command slice.
        /// </summary>
        /// <param name="requestPacket">Compounded request packet.</param>
        /// <returns>Compounded response packet.</returns>
        public Smb2CompoundPacket HandleCompoundRequestPacket(Smb2CompoundPacket requestPacket)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            WriteDiagnostic("Dispatching compounded request packet with " + requestPacket.Entries.Count + " entr" + (requestPacket.Entries.Count == 1 ? "y" : "ies") + ".");

            if ((requestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
            {
                throw new ProtocolValidationException("The first compounded SMB2 request cannot set RelatedOperations.", nameof(requestPacket));
            }

            bool anyRelatedEntries = false;
            bool anyUnrelatedEntriesAfterFirst = false;

            for (int index = 1; index < requestPacket.Entries.Count; index++)
            {
                if ((requestPacket.Entries[index].Header.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
                {
                    anyRelatedEntries = true;
                }
                else
                {
                    anyUnrelatedEntriesAfterFirst = true;
                }
            }

            if (anyRelatedEntries && anyUnrelatedEntriesAfterFirst)
            {
                throw new ProtocolValidationException("SMB2 compounded request chains cannot mix unrelated and related styles in the current surface.", nameof(requestPacket));
            }

            if (anyRelatedEntries)
            {
                WriteDiagnostic("Dispatching related compounded request packet.");
                return HandleRelatedCompoundRequestPacket(requestPacket);
            }

            List<Smb2CompoundPacketEntry> responseEntries = new List<Smb2CompoundPacketEntry>(requestPacket.Entries.Count);
            ulong compoundedSessionId = 0;

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[index];
                Smb2Header effectiveHeader = CloneHeader(requestEntry.Header);

                WriteDiagnostic(
                    "Dispatching request entry " +
                    (index + 1).ToString() +
                    "/" +
                    requestPacket.Entries.Count.ToString() +
                    ": command=" +
                    effectiveHeader.Command +
                    ", messageId=" +
                    effectiveHeader.MessageId +
                    ", sessionId=" +
                    effectiveHeader.SessionId +
                    ", treeId=" +
                    effectiveHeader.TreeId +
                    ", flags=" +
                    effectiveHeader.Flags +
                    ".");

                if (compoundedSessionId != 0 &&
                    effectiveHeader.SessionId == 0 &&
                    CommandRequiresSessionId(effectiveHeader.Command))
                {
                    effectiveHeader.SessionId = compoundedSessionId;
                }

                Smb2CompoundPacketEntry responseEntry = HandleCompoundRequestEntry(new Smb2CompoundPacketEntry(effectiveHeader, requestEntry.Payload));
                WriteDiagnostic(
                    "Completed request entry " +
                    (index + 1).ToString() +
                    "/" +
                    requestPacket.Entries.Count.ToString() +
                    ": command=" +
                    effectiveHeader.Command +
                    ", status=" +
                    responseEntry.Header.Status +
                    ", responseSessionId=" +
                    responseEntry.Header.SessionId +
                    ", responseTreeId=" +
                    responseEntry.Header.TreeId +
                    ".");
                responseEntries.Add(responseEntry);

                if (effectiveHeader.Command == Smb2Command.SessionSetup &&
                    responseEntry.Header.Status == NtStatus.Success &&
                    responseEntry.Header.SessionId != 0)
                {
                    compoundedSessionId = responseEntry.Header.SessionId;
                }
            }

            return new Smb2CompoundPacket(responseEntries);
        }

        /// <summary>
        /// Handle an SMB2 negotiate request.
        /// </summary>
        /// <param name="request">Client negotiate request.</param>
        /// <returns>Negotiated response.</returns>
        public Smb2NegotiateResponse HandleNegotiate(Smb2NegotiateRequest request)
        {
            Smb2NegotiateRequestValidator.Validate(request);
            SmbDialect[] advertisedDialects = GetAdvertisedDialects();

            if (advertisedDialects.Length == 0)
            {
                throw new InvalidOperationException("The configured server dialect range does not include any currently implemented SMB2 dialects.");
            }

            if (!SmbDialectCatalog.TrySelectHighestCommonSmb2Dialect(
                clientDialects: request.Dialects,
                minimumServerDialect: advertisedDialects[0],
                maximumServerDialect: advertisedDialects[advertisedDialects.Length - 1],
                negotiatedDialect: out SmbDialect negotiatedDialect))
            {
                throw new InvalidOperationException("No common SMB2 dialect is available for negotiation.");
            }

            Smb2SecurityMode securityMode = Smb2SecurityMode.SigningEnabled;

            if (Options.RequireSigning)
            {
                securityMode |= Smb2SecurityMode.SigningRequired;
            }

            Smb2NegotiateResponse response = new Smb2NegotiateResponse
            {
                SecurityMode = securityMode,
                Dialect = negotiatedDialect,
                ServerGuid = ServerGuid,
                Capabilities = negotiatedDialect >= SmbDialect.Smb21
                    ? Smb2GlobalCapabilities.LargeMtu
                    : Smb2GlobalCapabilities.None,
                MaxTransactSize = ImplementedMaxTransactSize,
                MaxReadSize = GetImplementedReadWriteSizeForDialect(negotiatedDialect),
                MaxWriteSize = GetImplementedReadWriteSizeForDialect(negotiatedDialect),
                SystemTime = ToFileTimeUtc(DateTimeOffset.UtcNow),
                ServerStartTime = _ServerStartTime,
                SecurityBuffer = Array.Empty<byte>()
            };

            _NegotiatedClientGuid = request.ClientGuid;
            _NegotiatedClientCapabilities = request.Capabilities;
            _NegotiatedClientSecurityMode = request.SecurityMode;
            _NegotiatedClientDialects = (SmbDialect[])request.Dialects.Clone();
            _NegotiatedServerSecurityMode = response.SecurityMode;
            _NegotiatedServerCapabilities = response.Capabilities;
            _NegotiatedDialect = response.Dialect;

            Smb2NegotiateResponseValidator.Validate(response);
            return response;
        }

        /// <summary>
        /// Handle an SMB2 session-setup request.
        /// </summary>
        /// <param name="sessionId">Current session identifier from the SMB2 header.</param>
        /// <param name="request">Session-setup request body.</param>
        /// <returns>Session-setup result.</returns>
        public OpenCifsServerSessionSetupResult HandleSessionSetup(ulong sessionId, Smb2SessionSetupRequest request)
        {
            Smb2SessionSetupRequestValidator.Validate(request);

            if (sessionId == 0)
            {
                return BeginSessionSetup(request);
            }

            return CompleteSessionSetup(sessionId, request);
        }

        /// <summary>
        /// Handle an SMB2 logoff request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="request">Logoff request body.</param>
        /// <returns>Operation result.</returns>
        public OpenCifsServerOperationResult<Smb2LogoffResponse> HandleLogoff(ulong sessionId, Smb2LogoffRequest request)
        {
            Smb2LogoffRequestValidator.Validate(request);

            if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                return new OpenCifsServerOperationResult<Smb2LogoffResponse>
                {
                    Status = NtStatus.AccessDenied,
                    Response = new Smb2LogoffResponse()
                };
            }

            CleanupSessionRecord(sessionRecord);
            _Sessions.Remove(sessionId);

            Smb2LogoffResponse response = new Smb2LogoffResponse();
            Smb2LogoffResponseValidator.Validate(response);
            return new OpenCifsServerOperationResult<Smb2LogoffResponse>
            {
                Status = NtStatus.Success,
                Response = response
            };
        }

        /// <summary>
        /// Handle an SMB2 echo request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="request">Echo request body.</param>
        /// <returns>Operation result.</returns>
        public OpenCifsServerOperationResult<Smb2EchoResponse> HandleEcho(ulong sessionId, Smb2EchoRequest request)
        {
            Smb2EchoRequestValidator.Validate(request);

            if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2EchoResponse());
            }

            Smb2EchoResponse response = new Smb2EchoResponse();
            Smb2EchoResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 tree-connect request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="request">Tree-connect request body.</param>
        /// <returns>Tree-connect result.</returns>
        public OpenCifsServerTreeConnectResult HandleTreeConnect(ulong sessionId, Smb2TreeConnectRequest request)
        {
            Smb2TreeConnectRequestValidator.Validate(request);
            WriteDiagnostic("Tree connect request received for session " + sessionId + " and path '" + request.Path + "'.");

            if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                WriteDiagnostic("Tree connect denied because session " + sessionId + " is not authenticated.");
                return new OpenCifsServerTreeConnectResult
                {
                    Status = NtStatus.AccessDenied,
                    TreeId = 0,
                    Response = new Smb2TreeConnectResponse()
                };
            }

            string shareName = ExtractShareName(request.Path);

            if (!TryGetEffectiveShare(shareName, out RegisteredShareRecord? shareRecord) || shareRecord == null)
            {
                WriteDiagnostic("Tree connect could not resolve share '" + shareName + "'.");
                return new OpenCifsServerTreeConnectResult
                {
                    Status = NtStatus.ObjectNameNotFound,
                    TreeId = 0,
                    Response = new Smb2TreeConnectResponse()
                };
            }

            if (Options.RequestCallbacks?.TreeConnectCallback != null)
            {
                NtStatus? callbackStatus = Options.RequestCallbacks.TreeConnectCallback(new OpenCifsServerTreeConnectContext
                {
                    SessionId = sessionId,
                    ShareName = shareRecord.ShareName,
                    ShareRootPath = shareRecord.RootPath,
                    Request = request
                });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    WriteDiagnostic("Tree connect callback rejected share '" + shareRecord.ShareName + "' with status " + callbackStatus.Value + ".");
                    return new OpenCifsServerTreeConnectResult
                    {
                        Status = callbackStatus.Value,
                        TreeId = 0,
                        Response = new Smb2TreeConnectResponse()
                    };
                }
            }

            uint treeId = _NextTreeId++;
            ServerTreeRecord treeRecord = new ServerTreeRecord
            {
                ShareName = shareRecord.ShareName,
                ShareRootPath = shareRecord.RootPath,
                Backend = shareRecord.Backend
            };
            treeRecord.State.Connect(treeId, shareRecord.ShareName);
            sessionRecord.Trees[treeId] = treeRecord;

            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse
            {
                ShareType = Smb2ShareType.Disk,
                ShareFlags = 0,
                Capabilities = 0,
                MaximalAccess = 0x001F01FF
            };
            Smb2TreeConnectResponseValidator.Validate(response);
            WriteDiagnostic("Tree connect accepted session " + sessionId + " for share '" + shareRecord.ShareName + "' with tree id " + treeId + ".");
            return new OpenCifsServerTreeConnectResult
            {
                Status = NtStatus.Success,
                TreeId = treeId,
                Response = response
            };
        }

        /// <summary>
        /// Handle an SMB2 create request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Create request body.</param>
        /// <returns>Create result.</returns>
        public OpenCifsServerOperationResult<Smb2CreateResponse> HandleCreate(ulong sessionId, uint treeId, Smb2CreateRequest request)
        {
            Smb2CreateRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord, out ServerTreeRecord? treeRecord) || sessionRecord == null || treeRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
            }

            Smb2CreateContext[] createContexts;

            try
            {
                createContexts = Smb2CreateContextCodec.Decode(request.CreateContexts);
            }
            catch (ProtocolEncodingException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            bool durableHandleRequested = false;
            bool hasUnsupportedDurableV2Context = false;
            bool hasUnsupportedLeaseV2Context = false;
            Smb2DurableHandleReconnectContext? durableHandleReconnectContext = null;
            Smb2CreateRequestLeaseContext? leaseRequestContext = null;

            for (int index = 0; index < createContexts.Length; index++)
            {
                Smb2CreateContext createContext = createContexts[index];

                if (Smb2DurableHandleRequestContext.IsMatch(createContext))
                {
                    durableHandleRequested = true;
                    continue;
                }

                if (Smb2DurableHandleReconnectContext.IsMatch(createContext))
                {
                    durableHandleReconnectContext = Smb2DurableHandleReconnectContext.ReadFrom(createContext);
                    continue;
                }

                if (IsCreateContextName(createContext, 0x44, 0x48, 0x32, 0x51) ||
                    IsCreateContextName(createContext, 0x44, 0x48, 0x32, 0x43))
                {
                    hasUnsupportedDurableV2Context = true;
                    continue;
                }

                if (Smb2CreateRequestLeaseContext.IsMatch(createContext))
                {
                    leaseRequestContext = Smb2CreateRequestLeaseContext.ReadFrom(createContext);
                    continue;
                }

                if (Smb2CreateRequestLeaseContext.HasLeaseContextName(createContext))
                {
                    hasUnsupportedLeaseV2Context = true;
                }
            }

            if (hasUnsupportedDurableV2Context || hasUnsupportedLeaseV2Context)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            bool isShareRootOpenRequest = IsShareRootOpenRequest(request);

            if (request.Name.Length == 0 && !isShareRootOpenRequest)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            if (!TryResolveShareFilePath(treeRecord.ShareRootPath, request.Name, out string? fullPath, out NtStatus pathStatus, allowShareRoot: isShareRootOpenRequest) || fullPath == null)
            {
                return CreateOperationResult(pathStatus, new Smb2CreateResponse());
            }

            if (durableHandleReconnectContext != null)
            {
                return HandleDurableReconnectCreate(sessionRecord, treeRecord, request, fullPath, durableHandleReconnectContext);
            }

            if (Options.RequestCallbacks?.CreateCallback != null)
            {
                NtStatus? callbackStatus = Options.RequestCallbacks.CreateCallback(new OpenCifsServerCreateContext
                {
                    SessionId = sessionId,
                    TreeId = treeId,
                    ShareName = treeRecord.ShareName,
                    FullPath = fullPath,
                    Request = request
                });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    return CreateOperationResult(callbackStatus.Value, new Smb2CreateResponse());
                }
            }

            bool existsDirectory = treeRecord.Backend.DirectoryExists(fullPath);
            bool existsFile = treeRecord.Backend.FileExists(fullPath);
            bool isDirectoryRequest = isShareRootOpenRequest ||
                (request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0 ||
                (existsDirectory && (request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) == 0);

            if (!isDirectoryRequest && existsDirectory)
            {
                return CreateOperationResult(NtStatus.FileIsADirectory, new Smb2CreateResponse());
            }

            if (isDirectoryRequest && existsFile)
            {
                NtStatus status = request.CreateDisposition == Smb2CreateDisposition.Create
                    ? NtStatus.ObjectNameCollision
                    : NtStatus.NotADirectory;
                return CreateOperationResult(status, new Smb2CreateResponse());
            }

            string? parentDirectory = Path.GetDirectoryName(fullPath);

            if (string.IsNullOrEmpty(parentDirectory) || !treeRecord.Backend.DirectoryExists(parentDirectory))
            {
                return CreateOperationResult(NtStatus.ObjectPathNotFound, new Smb2CreateResponse());
            }

            bool exists = isDirectoryRequest ? existsDirectory : existsFile;
            bool requiresWriteAccessForOpen = !isDirectoryRequest && (!exists ||
                request.CreateDisposition == Smb2CreateDisposition.Create ||
                request.CreateDisposition == Smb2CreateDisposition.OpenIf ||
                request.CreateDisposition == Smb2CreateDisposition.Overwrite ||
                request.CreateDisposition == Smb2CreateDisposition.OverwriteIf ||
                request.CreateDisposition == Smb2CreateDisposition.Supersede);
            bool canWrite = CanWrite(request.DesiredAccess);
            bool canRead = CanRead(request.DesiredAccess);
            bool canWriteData = CanWriteData(request.DesiredAccess);
            bool canReadData = CanReadData(request.DesiredAccess);
            bool canDelete = CanDelete(request.DesiredAccess);
            bool deleteOnClose = (request.CreateOptions & Smb2CreateOptions.DeleteOnClose) != 0;
            bool leaseRequested = !isDirectoryRequest &&
                request.RequestedOplockLevel == Smb2OplockLevel.Lease &&
                leaseRequestContext != null &&
                _NegotiatedDialect.HasValue &&
                _NegotiatedDialect.Value >= SmbDialect.Smb21;
            OpenCifsServerLeaseRecord? existingLeaseRecord = null;
            Smb2LeaseState grantedLeaseState = Smb2LeaseState.None;
            bool leaseBreakInProgress = false;

            if (leaseRequested)
            {
                _SharedState.TryGetLeaseRecord(_NegotiatedClientGuid, leaseRequestContext!.LeaseKey, out existingLeaseRecord);

                if (existingLeaseRecord != null &&
                    !string.Equals(existingLeaseRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }

                grantedLeaseState = DetermineGrantedCreateLeaseState(fullPath, existingLeaseRecord, NormalizeLeaseState(leaseRequestContext.LeaseState));
                leaseBreakInProgress = existingLeaseRecord != null && existingLeaseRecord.IsBreaking;
            }

            Smb2OplockLevel grantedOplockLevel = leaseRequested
                ? Smb2OplockLevel.Lease
                : DetermineGrantedCreateOplockLevel(request, isDirectoryRequest, fullPath);

            if (requiresWriteAccessForOpen && !canWrite)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
            }

            if (!TryValidateCreateOpenSemantics(fullPath, request.DesiredAccess, request.ShareAccess, out NtStatus openStatus))
            {
                return CreateOperationResult(openStatus, new Smb2CreateResponse());
            }

            FileMode fileMode;
            Smb2CreateAction createAction;

            if (isDirectoryRequest)
            {
                switch (request.CreateDisposition)
                {
                    case Smb2CreateDisposition.Create:
                        if (exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2CreateResponse());
                        }

                        if (!TryCreateBackingDirectory(treeRecord.Backend, fullPath, out NtStatus directoryCreateStatus))
                        {
                            return CreateOperationResult(directoryCreateStatus, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Open:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Opened;
                        break;
                    case Smb2CreateDisposition.OpenIf:
                        if (!exists)
                        {
                            if (!TryCreateBackingDirectory(treeRecord.Backend, fullPath, out NtStatus directoryOpenIfStatus))
                            {
                                return CreateOperationResult(directoryOpenIfStatus, new Smb2CreateResponse());
                            }

                            createAction = Smb2CreateAction.Created;
                        }
                        else
                        {
                            createAction = Smb2CreateAction.Opened;
                        }

                        fileMode = FileMode.Open;
                        break;
                    default:
                        return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }
            }
            else
            {
                switch (request.CreateDisposition)
                {
                    case Smb2CreateDisposition.Supersede:
                        fileMode = FileMode.Create;
                        createAction = exists ? Smb2CreateAction.Superseded : Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Open:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Opened;
                        break;
                    case Smb2CreateDisposition.Create:
                        if (exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.CreateNew;
                        createAction = Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.OpenIf:
                        fileMode = FileMode.OpenOrCreate;
                        createAction = exists ? Smb2CreateAction.Opened : Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Overwrite:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Truncate;
                        createAction = Smb2CreateAction.Overwritten;
                        break;
                    case Smb2CreateDisposition.OverwriteIf:
                        fileMode = FileMode.Create;
                        createAction = exists ? Smb2CreateAction.Overwritten : Smb2CreateAction.Created;
                        break;
                    default:
                        return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }
            }

            if (createAction == Smb2CreateAction.Created &&
                deleteOnClose &&
                (request.FileAttributes & ProtocolFileAttributes.ReadOnly) != 0)
            {
                if (isDirectoryRequest && !exists)
                {
                    DeleteBackingObjectIfPresent(treeRecord.Backend, fullPath);
                }

                return CreateOperationResult(NtStatus.CannotDelete, new Smb2CreateResponse());
            }

            FileAccess fileAccess = DetermineFileAccess(request.DesiredAccess);
            FileStream? stream = null;
            bool shouldApplyCreateFileAttributes = !isDirectoryRequest &&
                (createAction == Smb2CreateAction.Created ||
                 createAction == Smb2CreateAction.Overwritten ||
                 createAction == Smb2CreateAction.Superseded);

            if (!isDirectoryRequest)
            {
                try
                {
                    stream = treeRecord.Backend.OpenFile(fullPath, fileMode, fileAccess, FileShare.ReadWrite | FileShare.Delete);
                }
                catch (DirectoryNotFoundException)
                {
                    return CreateOperationResult(NtStatus.ObjectPathNotFound, new Smb2CreateResponse());
                }
                catch (FileNotFoundException)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }
                catch (UnauthorizedAccessException)
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
                catch (IOException)
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
            }

            if (shouldApplyCreateFileAttributes)
            {
                try
                {
                    treeRecord.Backend.SetAttributes(fullPath, NormalizeCreateFileAttributes(request.FileAttributes));
                }
                catch (UnauthorizedAccessException)
                {
                    stream?.Dispose();

                    if (createAction == Smb2CreateAction.Created)
                    {
                        DeleteBackingObjectIfPresent(treeRecord.Backend, fullPath);
                    }

                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
                catch (IOException)
                {
                    stream?.Dispose();

                    if (createAction == Smb2CreateAction.Created)
                    {
                        DeleteBackingObjectIfPresent(treeRecord.Backend, fullPath);
                    }

                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
            }

            bool durableHandleGranted = durableHandleRequested && grantedOplockLevel == Smb2OplockLevel.Batch;
            ulong fileId = _SharedState.AllocateFileId();
            OpenState openState = new OpenState();
            openState.Bind(fileId, fileId, request.Name.Length == 0 ? "\\" : request.Name);
            openState.SetOplockLevel(grantedOplockLevel);
            openState.SetDurable(durableHandleGranted);
            OpenCifsServerLeaseRecord? attachedLeaseRecord = null;

            if (leaseRequested && leaseRequestContext != null)
            {
                attachedLeaseRecord = existingLeaseRecord ?? _SharedState.GetOrAddLeaseRecord(_NegotiatedClientGuid, leaseRequestContext.LeaseKey, fullPath);
                attachedLeaseRecord.FullPath = fullPath;
                attachedLeaseRecord.LeaseState = grantedLeaseState;

                if (!leaseBreakInProgress)
                {
                    attachedLeaseRecord.PendingBreakLeaseState = grantedLeaseState;
                }

                attachedLeaseRecord.OpenCount++;
                openState.SetLease(attachedLeaseRecord.LeaseKey, grantedLeaseState);
            }

            ServerOpenRecord openRecord = new ServerOpenRecord
            {
                OwnerHost = this,
                SessionId = sessionId,
                TreeId = treeId,
                ShareName = treeRecord.ShareName,
                ShareRootPath = treeRecord.ShareRootPath,
                Backend = treeRecord.Backend,
                FullPath = fullPath,
                DesiredAccess = request.DesiredAccess,
                ShareAccess = request.ShareAccess,
                CanRead = canRead,
                CanWrite = canWrite,
                CanReadData = canReadData,
                CanWriteData = canWriteData,
                CanDelete = canDelete,
                IsDirectory = isDirectoryRequest,
                GrantedOplockLevel = grantedOplockLevel,
                PendingOplockBreakLevel = grantedOplockLevel,
                LeaseRecord = attachedLeaseRecord,
                Stream = stream,
                State = openState
            };
            sessionRecord.Opens[fileId] = openRecord;

            if (attachedLeaseRecord != null)
            {
                UpdateLeaseStateForTrackedOpens(attachedLeaseRecord);
            }

            if (deleteOnClose)
            {
                NtStatus deletePendingStatus = ApplyDeletePendingState(openRecord, deletePending: true);

                if (deletePendingStatus != NtStatus.Success)
                {
                    CloseOpenRecord(sessionRecord, fileId);
                    return CreateOperationResult(deletePendingStatus, new Smb2CreateResponse());
                }
            }

            if (!isDirectoryRequest && stream != null)
            {
                ulong currentLength = unchecked((ulong)Math.Max(0L, stream.Length));

                if (createAction == Smb2CreateAction.Opened)
                {
                    EnsureDeclaredAllocationSize(fullPath, currentLength);
                }
                else
                {
                    SetDeclaredAllocationSize(fullPath, currentLength, currentLength);
                }
            }

            FileMetadata metadata = BuildFileMetadata(treeRecord.Backend, fullPath);
            List<Smb2CreateContext> responseCreateContexts = new List<Smb2CreateContext>();

            if (durableHandleGranted)
            {
                responseCreateContexts.Add(Smb2DurableHandleResponseContext.Create());
            }

            if (attachedLeaseRecord != null)
            {
                responseCreateContexts.Add(new Smb2CreateResponseLeaseContext
                {
                    LeaseKey = attachedLeaseRecord.LeaseKey,
                    LeaseState = attachedLeaseRecord.LeaseState,
                    LeaseFlags = leaseBreakInProgress ? Smb2LeaseFlags.BreakInProgress : Smb2LeaseFlags.None
                }.ToCreateContext());
            }

            Smb2CreateResponse response = new Smb2CreateResponse
            {
                OplockLevel = grantedOplockLevel,
                Flags = 0,
                CreateAction = createAction,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                AllocationSize = metadata.AllocationSize,
                EndOfFile = metadata.EndOfFile,
                FileAttributes = metadata.FileAttributes,
                PersistentFileId = fileId,
                VolatileFileId = fileId,
                CreateContexts = responseCreateContexts.Count == 0
                    ? Array.Empty<byte>()
                    : Smb2CreateContextCodec.Encode(responseCreateContexts)
            };

            Smb2CreateResponseValidator.Validate(response);

            if (createAction == Smb2CreateAction.Created)
            {
                PublishNameChangeNotification(fullPath, isDirectoryRequest, FileNotifyAction.Added);
            }
            else if (createAction == Smb2CreateAction.Overwritten || createAction == Smb2CreateAction.Superseded)
            {
                PublishModifiedNotification(
                    fullPath,
                    FileNotifyChangeFilter.Size |
                    FileNotifyChangeFilter.LastWrite |
                    FileNotifyChangeFilter.Creation |
                    (shouldApplyCreateFileAttributes ? FileNotifyChangeFilter.Attributes : FileNotifyChangeFilter.None));
            }

            if (!isDirectoryRequest)
            {
                QueueOplockBreakNotificationsForConflictingOpens(fullPath, openRecord);
                QueueLeaseBreakNotificationsForConflictingOpens(fullPath, openRecord);
            }

            return CreateOperationResult(NtStatus.Success, response);
        }

        private OpenCifsServerOperationResult<Smb2CreateResponse> HandleDurableReconnectCreate(
            ServerSessionRecord sessionRecord,
            ServerTreeRecord treeRecord,
            Smb2CreateRequest request,
            string fullPath,
            Smb2DurableHandleReconnectContext reconnectContext)
        {
            if (request.Name.Length == 0 ||
                (request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            if (!_SharedState.TryTakeDetachedDurableOpen(reconnectContext.PersistentFileId, out OpenCifsServerDurableOpenRecord? durableOpenRecord) ||
                durableOpenRecord == null)
            {
                return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
            }

            bool reconnectAccepted = false;

            try
            {
                if (!string.Equals(durableOpenRecord.DurableOwnerUserName, sessionRecord.UserName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(durableOpenRecord.DurableOwnerUserDomain, sessionRecord.UserDomain, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }

                if (!string.Equals(durableOpenRecord.ShareName, treeRecord.ShareName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }

                if (durableOpenRecord.Stream == null)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }

                ulong volatileFileId = _SharedState.AllocateFileId();
                OpenState openState = new OpenState();
                openState.Bind(durableOpenRecord.PersistentFileId, volatileFileId, durableOpenRecord.RelativePath);
                openState.SetDeletePending(durableOpenRecord.IsDeletePending);
                openState.SetOplockLevel(durableOpenRecord.GrantedOplockLevel);
                openState.SetDurable(true);

                ServerOpenRecord openRecord = new ServerOpenRecord
                {
                    OwnerHost = this,
                    SessionId = sessionRecord.State.SessionId,
                    TreeId = treeRecord.State.TreeId,
                    ShareName = treeRecord.ShareName,
                    ShareRootPath = treeRecord.ShareRootPath,
                    Backend = treeRecord.Backend,
                    FullPath = durableOpenRecord.FullPath,
                    DesiredAccess = durableOpenRecord.DesiredAccess,
                    ShareAccess = durableOpenRecord.ShareAccess,
                    CanRead = durableOpenRecord.CanRead,
                    CanWrite = durableOpenRecord.CanWrite,
                    CanReadData = durableOpenRecord.CanReadData,
                    CanWriteData = durableOpenRecord.CanWriteData,
                    CanDelete = durableOpenRecord.CanDelete,
                    IsDirectory = false,
                    GrantedOplockLevel = durableOpenRecord.GrantedOplockLevel,
                    PendingOplockBreakLevel = durableOpenRecord.GrantedOplockLevel,
                    Stream = durableOpenRecord.Stream,
                    State = openState,
                    SuppressAccessTimeUpdates = durableOpenRecord.SuppressAccessTimeUpdates,
                    SuppressModificationTimeUpdates = durableOpenRecord.SuppressModificationTimeUpdates,
                    SuppressChangeTimeUpdates = durableOpenRecord.SuppressChangeTimeUpdates
                };

                for (int index = 0; index < durableOpenRecord.Locks.Count; index++)
                {
                    OpenCifsServerDetachedByteRangeLock detachedLock = durableOpenRecord.Locks[index];
                    openRecord.Locks.Add(new ServerByteRangeLock
                    {
                        OwnerVolatileFileId = volatileFileId,
                        Offset = detachedLock.Offset,
                        Length = detachedLock.Length,
                        IsShared = detachedLock.IsShared
                    });
                }

                durableOpenRecord.Stream = null;
                sessionRecord.Opens[volatileFileId] = openRecord;

                FileMetadata metadata = BuildFileMetadata(treeRecord.Backend, fullPath);
                Smb2CreateResponse response = new Smb2CreateResponse
                {
                    OplockLevel = durableOpenRecord.GrantedOplockLevel,
                    Flags = 0,
                    CreateAction = Smb2CreateAction.Opened,
                    CreationTime = metadata.CreationTime,
                    LastAccessTime = metadata.LastAccessTime,
                    LastWriteTime = metadata.LastWriteTime,
                    ChangeTime = metadata.ChangeTime,
                    AllocationSize = metadata.AllocationSize,
                    EndOfFile = metadata.EndOfFile,
                    FileAttributes = metadata.FileAttributes,
                    PersistentFileId = durableOpenRecord.PersistentFileId,
                    VolatileFileId = volatileFileId,
                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                    {
                        Smb2DurableHandleResponseContext.Create()
                    })
                };
                Smb2CreateResponseValidator.Validate(response);
                reconnectAccepted = true;
                return CreateOperationResult(NtStatus.Success, response);
            }
            finally
            {
                if (!reconnectAccepted)
                {
                    _SharedState.PutDetachedDurableOpen(durableOpenRecord);
                }
            }
        }

        /// <summary>
        /// Handle an SMB2 oplock-break acknowledgment request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Oplock-break acknowledgment body.</param>
        /// <returns>Oplock-break result.</returns>
        public OpenCifsServerOperationResult<Smb2OplockBreakResponse> HandleOplockBreakAcknowledgment(ulong sessionId, uint treeId, Smb2OplockBreakAcknowledgment request)
        {
            Smb2OplockBreakAcknowledgmentValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2OplockBreakResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2OplockBreakResponse());
            }

            if (!openRecord.IsOplockBreakInProgress)
            {
                return CreateOperationResult(NtStatus.InvalidDeviceState, new Smb2OplockBreakResponse());
            }

            if (request.OplockLevel != openRecord.PendingOplockBreakLevel)
            {
                return CreateOperationResult(NtStatus.InvalidOplockProtocol, new Smb2OplockBreakResponse());
            }

            openRecord.GrantedOplockLevel = request.OplockLevel;
            openRecord.PendingOplockBreakLevel = request.OplockLevel;
            openRecord.IsOplockBreakInProgress = false;

            Smb2OplockBreakResponse response = new Smb2OplockBreakResponse
            {
                OplockLevel = openRecord.GrantedOplockLevel,
                PersistentFileId = openRecord.State.PersistentFileId,
                VolatileFileId = openRecord.State.VolatileFileId
            };
            Smb2OplockBreakResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 lease-break acknowledgment request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Lease-break acknowledgment body.</param>
        /// <returns>Lease-break result.</returns>
        public OpenCifsServerOperationResult<Smb2LeaseBreakResponse> HandleLeaseBreakAcknowledgment(ulong sessionId, uint treeId, Smb2LeaseBreakAcknowledgment request)
        {
            Smb2LeaseBreakAcknowledgmentValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2LeaseBreakResponse());
            }

            if (!TryGetOpenByLeaseKey(sessionRecord, treeId, request.LeaseKey, out ServerOpenRecord? openRecord) ||
                openRecord == null ||
                openRecord.LeaseRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2LeaseBreakResponse());
            }

            OpenCifsServerLeaseRecord leaseRecord = openRecord.LeaseRecord;

            if (!leaseRecord.IsBreaking)
            {
                return CreateOperationResult(NtStatus.InvalidDeviceState, new Smb2LeaseBreakResponse());
            }

            if (NormalizeLeaseState(request.LeaseState) != leaseRecord.PendingBreakLeaseState)
            {
                return CreateOperationResult(NtStatus.InvalidOplockProtocol, new Smb2LeaseBreakResponse());
            }

            leaseRecord.LeaseState = NormalizeLeaseState(request.LeaseState);
            leaseRecord.PendingBreakLeaseState = leaseRecord.LeaseState;
            leaseRecord.IsBreaking = false;
            UpdateLeaseStateForTrackedOpens(leaseRecord);

            Smb2LeaseBreakResponse response = new Smb2LeaseBreakResponse
            {
                LeaseKey = leaseRecord.LeaseKey,
                LeaseState = leaseRecord.LeaseState
            };
            Smb2LeaseBreakResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 read request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Read request body.</param>
        /// <returns>Read result.</returns>
        public OpenCifsServerOperationResult<Smb2ReadResponse> HandleRead(ulong sessionId, uint treeId, Smb2ReadRequest request)
        {
            Smb2ReadRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2ReadResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2ReadResponse());
            }

            if (!openRecord.CanReadData)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2ReadResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (request.Length > Int32.MaxValue)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (request.Length > GetImplementedReadWriteSizeForCurrentDialect())
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (HasConflictingReadLock(openRecord, request.Offset, request.Length))
            {
                return CreateOperationResult(NtStatus.FileLockConflict, new Smb2ReadResponse());
            }

            byte[] buffer = new byte[(int)request.Length];
            int bytesRead;

            try
            {
                openRecord.Stream.Position = checked((long)request.Offset);
                bytesRead = openRecord.Stream.Read(buffer, 0, buffer.Length);
            }
            catch (ArgumentOutOfRangeException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }
            catch (IOException)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2ReadResponse());
            }

            if (bytesRead == 0)
            {
                return CreateOperationResult(NtStatus.EndOfFile, new Smb2ReadResponse());
            }

            if (bytesRead != buffer.Length)
            {
                Array.Resize(ref buffer, bytesRead);
            }

            PublishModifiedNotification(openRecord.FullPath, NoteTimestampMutation(openRecord, updateLastAccess: true));
            Smb2ReadResponse response = new Smb2ReadResponse
            {
                DataBuffer = buffer,
                DataRemaining = 0,
                Flags = 0
            };

            Smb2ReadResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 write request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Write request body.</param>
        /// <returns>Write result.</returns>
        public OpenCifsServerOperationResult<Smb2WriteResponse> HandleWrite(ulong sessionId, uint treeId, Smb2WriteRequest request)
        {
            Smb2WriteRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2WriteResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2WriteResponse());
            }

            if (!openRecord.CanWriteData)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2WriteResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }

            if (request.DataBuffer.Length > GetImplementedReadWriteSizeForCurrentDialect())
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }

            if (HasConflictingWriteLock(openRecord, request.Offset, (ulong)request.DataBuffer.Length))
            {
                return CreateOperationResult(NtStatus.FileLockConflict, new Smb2WriteResponse());
            }

            try
            {
                openRecord.Stream.Position = checked((long)request.Offset);
                openRecord.Stream.Write(request.DataBuffer, 0, request.DataBuffer.Length);
                EnsureDeclaredAllocationSize(openRecord.FullPath, unchecked((ulong)Math.Max(0L, openRecord.Stream.Length)));
            }
            catch (ArgumentOutOfRangeException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }
            catch (IOException)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2WriteResponse());
            }

            PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | NoteTimestampMutation(openRecord, updateLastWrite: true, updateChange: true));
            Smb2WriteResponse response = new Smb2WriteResponse
            {
                Count = (uint)request.DataBuffer.Length
            };

            Smb2WriteResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 flush request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Flush request body.</param>
        /// <returns>Flush result.</returns>
        public OpenCifsServerOperationResult<Smb2FlushResponse> HandleFlush(ulong sessionId, uint treeId, Smb2FlushRequest request)
        {
            Smb2FlushRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2FlushResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2FlushResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2FlushResponse());
            }

            try
            {
                openRecord.Stream.Flush();
            }
            catch (IOException)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2FlushResponse());
            }

            Smb2FlushResponse response = new Smb2FlushResponse();
            Smb2FlushResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 lock request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Lock request body.</param>
        /// <returns>Lock result.</returns>
        public OpenCifsServerOperationResult<Smb2LockResponse> HandleLock(ulong sessionId, uint treeId, Smb2LockRequest request)
        {
            Smb2LockRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2LockResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2LockResponse());
            }

            if (openRecord.IsDirectory)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2LockResponse());
            }

            NtStatus lockStatus = ApplyByteRangeLocks(openRecord, request.Locks);

            if (lockStatus != NtStatus.Success)
            {
                return CreateOperationResult(lockStatus, new Smb2LockResponse());
            }

            Smb2LockResponse response = new Smb2LockResponse();
            Smb2LockResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 IOCTL request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">IOCTL request body.</param>
        /// <returns>IOCTL result.</returns>
        public OpenCifsServerOperationResult<Smb2IoctlResponse> HandleIoctl(ulong sessionId, uint treeId, Smb2IoctlRequest request)
        {
            Smb2IoctlRequestValidator.Validate(request);
            Smb2IoctlResponse defaultResponse = CreateIoctlResponse(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, defaultResponse);
            }

            if (request.Flags != Smb2IoctlFlags.IsFsctl)
            {
                return CreateOperationResult(NtStatus.NotSupported, defaultResponse);
            }

            bool wildcardFileId = IsWildcardIoctlFileId(request.PersistentFileId, request.VolatileFileId);
            bool connectionScopedFsctl = IsConnectionScopedFsctl(request.CtlCode);

            if (connectionScopedFsctl && !wildcardFileId)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            ServerOpenRecord? openRecord = null;

            if (!connectionScopedFsctl &&
                (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out openRecord) || openRecord == null))
            {
                return CreateOperationResult(NtStatus.FileClosed, defaultResponse);
            }

            if (request.InputBuffer.Length > ImplementedMaxTransactSize ||
                request.MaxInputResponse > ImplementedMaxTransactSize ||
                request.MaxOutputResponse > ImplementedMaxTransactSize)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (Options.RequestCallbacks?.IoctlCallback != null)
            {
                OpenCifsServerIoctlCallbackResult? callbackResult = Options.RequestCallbacks.IoctlCallback(new OpenCifsServerIoctlContext
                {
                    SessionId = sessionId,
                    TreeId = treeId,
                    ShareName = openRecord?.ShareName,
                    FullPath = openRecord?.FullPath,
                    Request = request
                });

                if (callbackResult != null)
                {
                    Smb2IoctlResponse callbackResponse = callbackResult.Response ?? CreateIoctlResponse(request);
                    callbackResponse.CtlCode = request.CtlCode;
                    callbackResponse.PersistentFileId = request.PersistentFileId;
                    callbackResponse.VolatileFileId = request.VolatileFileId;
                    Smb2IoctlResponseValidator.Validate(callbackResponse);
                    return CreateOperationResult(callbackResult.Status, callbackResponse);
                }
            }

            WriteDiagnostic(
                "IOCTL request received for session " +
                sessionId.ToString() +
                ", tree " +
                treeId.ToString() +
                ", ctlCode=0x" +
                request.CtlCode.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                ", wildcardFileId=" +
                wildcardFileId +
                ".");

            switch ((FsctlCode)request.CtlCode)
            {
                case FsctlCode.ValidateNegotiateInfo:
                    return HandleValidateNegotiateInfoIoctl(request);
                case FsctlCode.SrvEnumerateSnapshots:
                    return HandleEnumerateSnapshotsIoctl(request, openRecord!);
                default:
                    return CreateOperationResult(NtStatus.NotSupported, defaultResponse);
            }
        }

        /// <summary>
        /// Handle an SMB2 close request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Close request body.</param>
        /// <returns>Close result.</returns>
        public OpenCifsServerOperationResult<Smb2CloseResponse> HandleClose(ulong sessionId, uint treeId, Smb2CloseRequest request)
        {
            Smb2CloseRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2CloseResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2CloseResponse());
            }

            FileMetadata metadata = default;

            if ((request.Flags & Smb2CloseFlags.PostQueryAttributes) != 0)
            {
                metadata = BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
            }

            CloseOpenRecord(sessionRecord, request.VolatileFileId);
            Smb2CloseResponse response = new Smb2CloseResponse
            {
                Flags = request.Flags,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                AllocationSize = metadata.AllocationSize,
                EndOfFile = metadata.EndOfFile,
                FileAttributes = metadata.FileAttributes
            };

            Smb2CloseResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 query-info request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Query-info request body.</param>
        /// <returns>Query-info result.</returns>
        public OpenCifsServerOperationResult<Smb2QueryInfoResponse> HandleQueryInfo(ulong sessionId, uint treeId, Smb2QueryInfoRequest request)
        {
            Smb2QueryInfoRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryInfoResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2QueryInfoResponse());
            }

            byte[] outputBuffer;

            if (request.InputBuffer.Length != 0 || request.AdditionalInformation != 0 || request.Flags != 0)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2QueryInfoResponse());
            }

            switch (request.InfoType)
            {
                case Smb2InfoType.File:
                    switch (request.FileInfoClass)
                    {
                        case FileInformationClass.BasicInformation:
                            if (!CanReadAttributes(openRecord.DesiredAccess))
                            {
                                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryInfoResponse());
                            }

                            FileMetadata basicMetadata = BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
                            outputBuffer = new FileBasicInformation
                            {
                                CreationTime = basicMetadata.CreationTime,
                                LastAccessTime = basicMetadata.LastAccessTime,
                                LastWriteTime = basicMetadata.LastWriteTime,
                                ChangeTime = basicMetadata.ChangeTime,
                                FileAttributes = basicMetadata.FileAttributes
                            }.ToByteArray();
                            break;
                        case FileInformationClass.StandardInformation:
                            FileMetadata standardMetadata = BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
                            outputBuffer = new FileStandardInformation
                            {
                                AllocationSize = standardMetadata.AllocationSize,
                                EndOfFile = standardMetadata.EndOfFile,
                                NumberOfLinks = 1,
                                DeletePending = openRecord.State.IsDeletePending,
                                Directory = openRecord.IsDirectory
                            }.ToByteArray();
                            break;
                        case FileInformationClass.InternalInformation:
                            outputBuffer = new FileInternalInformation
                            {
                                IndexNumber = openRecord.State.PersistentFileId
                            }.ToByteArray();
                            break;
                        case FileInformationClass.NameInformation:
                            outputBuffer = new FileNameInformation
                            {
                                FileName = openRecord.State.Path
                            }.ToByteArray();
                            break;
                        case FileInformationClass.NetworkOpenInformation:
                            if (!CanReadAttributes(openRecord.DesiredAccess))
                            {
                                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryInfoResponse());
                            }

                            FileMetadata networkMetadata = BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
                            outputBuffer = new FileNetworkOpenInformation
                            {
                                CreationTime = networkMetadata.CreationTime,
                                LastAccessTime = networkMetadata.LastAccessTime,
                                LastWriteTime = networkMetadata.LastWriteTime,
                                ChangeTime = networkMetadata.ChangeTime,
                                AllocationSize = networkMetadata.AllocationSize,
                                EndOfFile = networkMetadata.EndOfFile,
                                FileAttributes = networkMetadata.FileAttributes
                            }.ToByteArray();
                            break;
                        case FileInformationClass.AllInformation:
                            if (!CanReadAttributes(openRecord.DesiredAccess))
                            {
                                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryInfoResponse());
                            }

                            FileMetadata allMetadata = BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
                            outputBuffer = new FileAllInformation
                            {
                                BasicInformation = new FileBasicInformation
                                {
                                    CreationTime = allMetadata.CreationTime,
                                    LastAccessTime = allMetadata.LastAccessTime,
                                    LastWriteTime = allMetadata.LastWriteTime,
                                    ChangeTime = allMetadata.ChangeTime,
                                    FileAttributes = allMetadata.FileAttributes
                                },
                                StandardInformation = new FileStandardInformation
                                {
                                    AllocationSize = allMetadata.AllocationSize,
                                    EndOfFile = allMetadata.EndOfFile,
                                    NumberOfLinks = 1,
                                    DeletePending = openRecord.State.IsDeletePending,
                                    Directory = openRecord.IsDirectory
                                },
                                InternalIndexNumber = openRecord.State.PersistentFileId,
                                EaSize = 0,
                                AccessFlags = openRecord.DesiredAccess,
                                CurrentByteOffset = 0,
                                Mode = 0,
                                AlignmentRequirement = 0,
                                NameInformation = new FileNameInformation
                                {
                                    FileName = openRecord.State.Path
                                }
                            }.ToByteArray();
                            break;
                        default:
                            return CreateOperationResult(NtStatus.NotSupported, new Smb2QueryInfoResponse());
                    }

                    break;
                case Smb2InfoType.FileSystem:
                    switch ((FileSystemInformationClass)(byte)request.FileInfoClass)
                    {
                        case FileSystemInformationClass.VolumeInformation:
                            outputBuffer = BuildFileSystemVolumeInformation(openRecord.ShareRootPath, openRecord.ShareName).ToByteArray();
                            break;
                        case FileSystemInformationClass.SizeInformation:
                            outputBuffer = BuildFileSystemSizeInformation(openRecord.ShareRootPath).ToByteArray();
                            break;
                        case FileSystemInformationClass.DeviceInformation:
                            outputBuffer = BuildFileSystemDeviceInformation().ToByteArray();
                            break;
                        case FileSystemInformationClass.AttributeInformation:
                            outputBuffer = BuildFileSystemAttributeInformation(openRecord.Backend, openRecord.ShareRootPath).ToByteArray();
                            break;
                        case FileSystemInformationClass.FullSizeInformation:
                            outputBuffer = BuildFileSystemFullSizeInformation(openRecord.ShareRootPath).ToByteArray();
                            break;
                        case FileSystemInformationClass.SectorSizeInformation:
                            outputBuffer = BuildFileSystemSectorSizeInformation().ToByteArray();
                            break;
                        default:
                            return CreateOperationResult(NtStatus.NotSupported, new Smb2QueryInfoResponse());
                    }

                    break;
                default:
                    return CreateOperationResult(NtStatus.NotSupported, new Smb2QueryInfoResponse());
            }

            if (request.OutputBufferLength < outputBuffer.Length)
            {
                return CreateOperationResult(NtStatus.BufferTooSmall, new Smb2QueryInfoResponse());
            }

            Smb2QueryInfoResponse response = new Smb2QueryInfoResponse
            {
                OutputBuffer = outputBuffer
            };
            Smb2QueryInfoResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        private static FileFsSizeInformation BuildFileSystemSizeInformation(string shareRootPath)
        {
            VolumeCapacitySnapshot snapshot = GetVolumeCapacitySnapshot(shareRootPath);

            return new FileFsSizeInformation
            {
                TotalAllocationUnits = snapshot.TotalAllocationUnits,
                AvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                SectorsPerAllocationUnit = FileSystemSectorsPerAllocationUnit,
                BytesPerSector = FileSystemBytesPerSector
            };
        }

        private static FileFsVolumeInformation BuildFileSystemVolumeInformation(string shareRootPath, string shareName)
        {
            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            string volumeLabel = string.Empty;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady)
                    {
                        volumeLabel = drive.VolumeLabel;
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            if (string.IsNullOrWhiteSpace(volumeLabel))
            {
                volumeLabel = shareName;
            }

            string volumeRoot = GetVolumeRoot(shareRootPath);
            DateTime creationTimeUtc;

            try
            {
                creationTimeUtc = Directory.GetCreationTimeUtc(volumeRoot);
            }
            catch (IOException)
            {
                creationTimeUtc = DateTime.UnixEpoch;
            }
            catch (UnauthorizedAccessException)
            {
                creationTimeUtc = DateTime.UnixEpoch;
            }

            if (creationTimeUtc.Kind != DateTimeKind.Utc)
            {
                creationTimeUtc = creationTimeUtc.ToUniversalTime();
            }

            if (creationTimeUtc < DateTime.FromFileTimeUtc(0))
            {
                creationTimeUtc = DateTime.FromFileTimeUtc(0);
            }

            return new FileFsVolumeInformation
            {
                VolumeCreationTime = unchecked((ulong)creationTimeUtc.ToFileTimeUtc()),
                VolumeSerialNumber = ComputeOpaqueVolumeSerialNumber(volumeRoot),
                SupportsObjects = false,
                VolumeLabel = volumeLabel
            };
        }

        private static FileFsDeviceInformation BuildFileSystemDeviceInformation()
        {
            return new FileFsDeviceInformation
            {
                DeviceType = FileSystemDeviceType.Disk,
                Characteristics = FileSystemDeviceCharacteristics.RemoteDevice | FileSystemDeviceCharacteristics.DeviceIsMounted
            };
        }

        private static FileFsAttributeInformation BuildFileSystemAttributeInformation(OpenCifsServerShareBackend backend, string shareRootPath)
        {
            FileSystemAttributesFlags attributes =
                FileSystemAttributesFlags.CasePreservedNames |
                FileSystemAttributesFlags.UnicodeOnDisk |
                FileSystemAttributesFlags.PersistentAcls |
                FileSystemAttributesFlags.SupportsHardLinks |
                FileSystemAttributesFlags.SupportsExtendedAttributes |
                FileSystemAttributesFlags.SupportsOpenByFileId;

            if (backend.Capabilities.SupportsNamedStreams)
            {
                attributes |= FileSystemAttributesFlags.NamedStreams;
            }

            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            string fileSystemName = DefaultFileSystemName;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady && !string.IsNullOrWhiteSpace(drive.DriveFormat))
                    {
                        fileSystemName = drive.DriveFormat;
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            return new FileFsAttributeInformation
            {
                FileSystemAttributes = attributes,
                MaximumComponentNameLength = FileSystemMaximumComponentNameLength,
                FileSystemName = fileSystemName
            };
        }

        private static FileFsFullSizeInformation BuildFileSystemFullSizeInformation(string shareRootPath)
        {
            VolumeCapacitySnapshot snapshot = GetVolumeCapacitySnapshot(shareRootPath);
            return new FileFsFullSizeInformation
            {
                TotalAllocationUnits = snapshot.TotalAllocationUnits,
                CallerAvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                ActualAvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                SectorsPerAllocationUnit = FileSystemSectorsPerAllocationUnit,
                BytesPerSector = FileSystemBytesPerSector
            };
        }

        private static FileFsSectorSizeInformation BuildFileSystemSectorSizeInformation()
        {
            return new FileFsSectorSizeInformation
            {
                LogicalBytesPerSector = FileSystemBytesPerSector,
                PhysicalBytesPerSectorForAtomicity = FileSystemBytesPerSector,
                PhysicalBytesPerSectorForPerformance = FileSystemBytesPerSector,
                FileSystemEffectivePhysicalBytesPerSectorForAtomicity = FileSystemBytesPerSector,
                Flags = FileSystemSectorSizeFlags.AlignedDevice | FileSystemSectorSizeFlags.PartitionAlignedOnDevice,
                ByteOffsetForSectorAlignment = 0,
                ByteOffsetForPartitionAlignment = 0
            };
        }

        private static VolumeCapacitySnapshot GetVolumeCapacitySnapshot(string shareRootPath)
        {
            const ulong bytesPerAllocationUnit = FileSystemBytesPerSector * FileSystemSectorsPerAllocationUnit;

            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            ulong totalAllocationUnits = 0;
            ulong availableAllocationUnits = 0;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady)
                    {
                        totalAllocationUnits = unchecked((ulong)Math.Max(0L, drive.TotalSize / (long)bytesPerAllocationUnit));
                        availableAllocationUnits = unchecked((ulong)Math.Max(0L, drive.AvailableFreeSpace / (long)bytesPerAllocationUnit));
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            return new VolumeCapacitySnapshot
            {
                TotalAllocationUnits = totalAllocationUnits,
                AvailableAllocationUnits = availableAllocationUnits
            };
        }

        private static DriveInfo? TryGetDriveInfo(string shareRootPath)
        {
            string volumeRoot = GetVolumeRoot(shareRootPath);

            try
            {
                return new DriveInfo(volumeRoot);
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static string GetVolumeRoot(string shareRootPath)
        {
            return Path.GetPathRoot(shareRootPath) ?? shareRootPath;
        }

        private static uint ComputeOpaqueVolumeSerialNumber(string volumeRoot)
        {
            string normalizedVolumeRoot = volumeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToUpperInvariant();
            uint hash = 2166136261;

            for (int index = 0; index < normalizedVolumeRoot.Length; index++)
            {
                hash ^= normalizedVolumeRoot[index];
                hash *= 16777619;
            }

            return hash;
        }

        /// <summary>
        /// Handle an SMB2 query-directory request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Query-directory request body.</param>
        /// <returns>Query-directory result.</returns>
        public OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> HandleQueryDirectory(ulong sessionId, uint treeId, Smb2QueryDirectoryRequest request)
        {
            WriteDiagnostic(
                "Query-directory request received for session " +
                sessionId +
                ", tree " +
                treeId +
                ", info class " +
                request.FileInfoClass +
                " (0x" +
                ((byte)request.FileInfoClass).ToString("X2") +
                "), pattern '" +
                request.FileNamePattern +
                "'.");
            Smb2QueryDirectoryRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryDirectoryResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2QueryDirectoryResponse());
            }

            if (Options.RequestCallbacks?.QueryDirectoryCallback != null)
            {
                NtStatus? callbackStatus = Options.RequestCallbacks.QueryDirectoryCallback(new OpenCifsServerQueryDirectoryContext
                {
                    SessionId = sessionId,
                    TreeId = treeId,
                    ShareName = openRecord.ShareName,
                    FullPath = openRecord.FullPath,
                    Request = request
                });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    return CreateOperationResult(callbackStatus.Value, new Smb2QueryDirectoryResponse());
                }
            }

            if (!openRecord.IsDirectory)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2QueryDirectoryResponse());
            }

            if (!CanListDirectory(openRecord.DesiredAccess))
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryDirectoryResponse());
            }

            switch (request.FileInfoClass)
            {
                case FileInformationClass.DirectoryInformation:
                case FileInformationClass.FullDirectoryInformation:
                case FileInformationClass.BothDirectoryInformation:
                case FileInformationClass.IdBothDirectoryInformation:
                case FileInformationClass.IdFullDirectoryInformation:
                    break;
                default:
                    return CreateOperationResult(NtStatus.InvalidInfoClass, new Smb2QueryDirectoryResponse());
            }

            bool restartScan = (request.Flags & (Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.Reopen)) != 0;
            bool hadExistingEnumeration = !string.IsNullOrEmpty(openRecord.DirectoryEnumerationPattern);
            string pattern;

            if (restartScan)
            {
                pattern = request.FileNamePattern.Length != 0
                    ? request.FileNamePattern
                    : (hadExistingEnumeration ? openRecord.DirectoryEnumerationPattern! : "*");
                openRecord.DirectoryEnumerationPattern = pattern;
                openRecord.DirectoryEnumerationIndex = 0;
            }
            else if (hadExistingEnumeration)
            {
                pattern = openRecord.DirectoryEnumerationPattern!;
            }
            else
            {
                pattern = request.FileNamePattern.Length != 0 ? request.FileNamePattern : "*";
                openRecord.DirectoryEnumerationPattern = pattern;
                openRecord.DirectoryEnumerationIndex = 0;
            }

            List<FileSystemInfo> matchingEntries = EnumerateMatchingDirectoryEntries(openRecord.Backend, openRecord.FullPath, pattern);
            bool firstPassForPattern = restartScan || !hadExistingEnumeration;

            if (matchingEntries.Count == 0)
            {
                return CreateOperationResult(firstPassForPattern ? NtStatus.NoSuchFile : NtStatus.NoMoreFiles, new Smb2QueryDirectoryResponse());
            }

            int startIndex = firstPassForPattern ? 0 : openRecord.DirectoryEnumerationIndex;

            if (startIndex >= matchingEntries.Count)
            {
                return CreateOperationResult(NtStatus.NoMoreFiles, new Smb2QueryDirectoryResponse());
            }

            bool returnSingleEntry = (request.Flags & Smb2QueryDirectoryFlags.ReturnSingleEntry) != 0;
            byte[] outputBuffer;
            int returnedEntryCount;
            NtStatus bufferStatus = TryBuildDirectoryEnumerationBuffer(
                openRecord.Backend,
                request.FileInfoClass,
                matchingEntries,
                startIndex,
                request.OutputBufferLength,
                returnSingleEntry,
                out outputBuffer,
                out returnedEntryCount);

            if (bufferStatus != NtStatus.Success)
            {
                return CreateOperationResult(bufferStatus, new Smb2QueryDirectoryResponse());
            }

            openRecord.DirectoryEnumerationIndex = startIndex + returnedEntryCount;
            Smb2QueryDirectoryResponse response = new Smb2QueryDirectoryResponse
            {
                OutputBuffer = outputBuffer
            };
            Smb2QueryDirectoryResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 set-info request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Set-info request body.</param>
        /// <returns>Set-info result.</returns>
        public OpenCifsServerOperationResult<Smb2SetInfoResponse> HandleSetInfo(ulong sessionId, uint treeId, Smb2SetInfoRequest request)
        {
            Smb2SetInfoRequestValidator.Validate(request);

            if (!TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord? sessionRecord) || sessionRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }

            if (!TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord? openRecord) || openRecord == null)
            {
                return CreateOperationResult(NtStatus.FileClosed, new Smb2SetInfoResponse());
            }

            if (Options.RequestCallbacks?.SetInfoCallback != null)
            {
                NtStatus? callbackStatus = Options.RequestCallbacks.SetInfoCallback(new OpenCifsServerSetInfoContext
                {
                    SessionId = sessionId,
                    TreeId = treeId,
                    ShareName = openRecord.ShareName,
                    FullPath = openRecord.FullPath,
                    Request = request
                });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    return CreateOperationResult(callbackStatus.Value, new Smb2SetInfoResponse());
                }
            }

            try
            {
                switch (request.FileInfoClass)
                {
                    case FileInformationClass.BasicInformation:
                        if (!CanWriteAttributes(openRecord.DesiredAccess))
                        {
                            return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
                        }

                        FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(request.Buffer);

                        NtStatus basicInformationStatus = ApplyFileBasicInformation(openRecord, basicInformation, out FileNotifyChangeFilter basicInformationFilter);

                        if (basicInformationStatus != NtStatus.Success)
                        {
                            return CreateOperationResult(basicInformationStatus, new Smb2SetInfoResponse());
                        }

                        PublishModifiedNotification(openRecord.FullPath, basicInformationFilter);

                        break;
                    case FileInformationClass.AllocationInformation:
                        if (!CanWriteData(openRecord.DesiredAccess))
                        {
                            return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
                        }

                        if (openRecord.IsDirectory || openRecord.Stream == null)
                        {
                            return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
                        }

                        ApplyFileAllocationInformation(openRecord, FileAllocationInformation.ReadFrom(request.Buffer));
                        break;
                    case FileInformationClass.EndOfFileInformation:
                        if (!CanWriteData(openRecord.DesiredAccess))
                        {
                            return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
                        }

                        if (openRecord.IsDirectory || openRecord.Stream == null)
                        {
                            return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
                        }

                        ApplyFileEndOfFileInformation(openRecord, FileEndOfFileInformation.ReadFrom(request.Buffer));
                        break;
                    case FileInformationClass.DispositionInformation:
                        if (!CanDelete(openRecord.DesiredAccess))
                        {
                            return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
                        }

                        FileDispositionInformation dispositionInformation = FileDispositionInformation.ReadFrom(request.Buffer);
                        NtStatus dispositionStatus = ApplyDeletePendingState(openRecord, dispositionInformation.DeletePending);

                        if (dispositionStatus != NtStatus.Success)
                        {
                            return CreateOperationResult(dispositionStatus, new Smb2SetInfoResponse());
                        }

                        break;
                    case FileInformationClass.RenameInformation:
                        if (!CanDelete(openRecord.DesiredAccess))
                        {
                            return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
                        }

                        OpenCifsServerOperationResult<Smb2SetInfoResponse>? renameResult = TryApplyRenameInformation(openRecord, FileRenameInformationType2.ReadFrom(request.Buffer));

                        if (renameResult != null)
                        {
                            return renameResult;
                        }

                        break;
                    default:
                        return CreateOperationResult(NtStatus.NotSupported, new Smb2SetInfoResponse());
                }
            }
            catch (ProtocolEncodingException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
            }
            catch (ArgumentOutOfRangeException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
            }
            catch (UnauthorizedAccessException)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }
            catch (IOException)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }

            Smb2SetInfoResponse response = new Smb2SetInfoResponse();
            Smb2SetInfoResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        /// <summary>
        /// Handle an SMB2 tree-disconnect request.
        /// </summary>
        /// <param name="sessionId">Session identifier from the SMB2 header.</param>
        /// <param name="treeId">Tree identifier from the SMB2 header.</param>
        /// <param name="request">Tree-disconnect request body.</param>
        /// <returns>Operation result.</returns>
        public OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> HandleTreeDisconnect(ulong sessionId, uint treeId, Smb2TreeDisconnectRequest request)
        {
            Smb2TreeDisconnectRequestValidator.Validate(request);

            if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                return new OpenCifsServerOperationResult<Smb2TreeDisconnectResponse>
                {
                    Status = NtStatus.AccessDenied,
                    Response = new Smb2TreeDisconnectResponse()
                };
            }

            if (!sessionRecord.Trees.TryGetValue(treeId, out ServerTreeRecord? treeRecord) || treeRecord == null)
            {
                return new OpenCifsServerOperationResult<Smb2TreeDisconnectResponse>
                {
                    Status = NtStatus.ObjectNameNotFound,
                    Response = new Smb2TreeDisconnectResponse()
                };
            }

            CleanupTreeOpenRecords(sessionRecord, treeId);
            treeRecord.State.Disconnect();
            treeRecord.State.Dispose();
            sessionRecord.Trees.Remove(treeId);

            Smb2TreeDisconnectResponse response = new Smb2TreeDisconnectResponse();
            Smb2TreeDisconnectResponseValidator.Validate(response);
            return new OpenCifsServerOperationResult<Smb2TreeDisconnectResponse>
            {
                Status = NtStatus.Success,
                Response = response
            };
        }

        private OpenCifsServerSessionSetupResult BeginSessionSetup(Smb2SessionSetupRequest request)
        {
            if (!TryParseInitialSessionSetupToken(request.SecurityBuffer, out InitialSessionSetupToken? initialToken, out NtStatus parseStatus) || initialToken == null)
            {
                return CreateSessionSetupResult(parseStatus, 0, new Smb2SessionSetupResponse());
            }

            if (initialToken.Flavor == SessionSetupFlavor.LegacyOpenCifs)
            {
                return BeginLegacySessionSetup(initialToken);
            }

            return BeginStandardSessionSetup(initialToken);
        }

        private OpenCifsServerSessionSetupResult CompleteSessionSetup(ulong sessionId, Smb2SessionSetupRequest request)
        {
            if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord))
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
            OpenCifsNtlmNegotiateToken negotiateToken = initialToken.LegacyNegotiateToken!;
            SpnegoNegTokenInit initToken = initialToken.SpnegoInitToken!;
            ulong assignedSessionId = _NextSessionId++;
            byte[] serverChallenge = new byte[8];
            RandomNumberGenerator.Fill(serverChallenge);

            ServerSessionRecord sessionRecord = new ServerSessionRecord
            {
                SessionSetupFlavor = SessionSetupFlavor.LegacyOpenCifs,
                UserName = negotiateToken.UserName,
                UserDomain = negotiateToken.UserDomain,
                ServerChallenge = serverChallenge,
                ExpectedServerName = Options.ServerName,
                ExpectedUserDomain = negotiateToken.UserDomain
            };
            sessionRecord.State.Bind(assignedSessionId);
            _Sessions[assignedSessionId] = sessionRecord;

            OpenCifsNtlmChallengeToken challengeToken = new OpenCifsNtlmChallengeToken
            {
                ServerChallenge = serverChallenge,
                ServerName = Options.ServerName,
                TargetDomain = negotiateToken.UserDomain
            };
            SpnegoNegTokenResp responseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(
                request: initToken,
                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                mechanismResponseToken: challengeToken.ToByteArray(),
                completed: false);
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
            ulong assignedSessionId = _NextSessionId++;
            byte[] serverChallenge = new byte[8];
            RandomNumberGenerator.Fill(serverChallenge);
            string expectedServerName = Options.ServerName;
            string expectedUserDomain = DetermineChallengeTargetDomain();
            NtlmChallengeMessage challengeMessage;

            try
            {
                challengeMessage = CreateStandardChallengeMessage(initialToken.StandardNegotiateMessage!, serverChallenge, expectedServerName, expectedUserDomain);
            }
            catch (ProtocolEncodingException)
            {
                return CreateSessionSetupResult(NtStatus.InvalidParameter, 0, new Smb2SessionSetupResponse());
            }

            byte[] challengeBytes = challengeMessage.ToByteArray();
            ServerSessionRecord sessionRecord = new ServerSessionRecord
            {
                SessionSetupFlavor = initialToken.Flavor,
                ServerChallenge = serverChallenge,
                ExpectedServerName = expectedServerName,
                ExpectedUserDomain = expectedUserDomain,
                NegotiateMessage = initialToken.StandardNegotiateMessageBytes,
                ChallengeMessage = challengeBytes
            };
            sessionRecord.State.Bind(assignedSessionId);
            _Sessions[assignedSessionId] = sessionRecord;

            byte[] responseSecurityBuffer = initialToken.Flavor == SessionSetupFlavor.RawNtlm
                ? challengeBytes
                : SpnegoTokenCodec.EncodeNegTokenResp(SpnegoMechanismNegotiator.CreateNegotiationResponse(
                    request: initialToken.SpnegoInitToken!,
                    supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                    mechanismResponseToken: challengeBytes,
                    completed: false));

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
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.InvalidParameter, sessionId, new Smb2SessionSetupResponse());
            }

            if (responseToken.ResponseToken == null)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.InvalidParameter, sessionId, new Smb2SessionSetupResponse());
            }

            OpenCifsNtlmAuthenticateToken authenticateToken;

            try
            {
                authenticateToken = OpenCifsNtlmAuthenticateToken.ReadFrom(responseToken.ResponseToken);
            }
            catch (ProtocolEncodingException)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.InvalidParameter, sessionId, new Smb2SessionSetupResponse());
            }

            if (!string.Equals(authenticateToken.UserName, sessionRecord.UserName, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(authenticateToken.UserDomain, sessionRecord.UserDomain, StringComparison.OrdinalIgnoreCase))
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            if (!TryGetAccount(authenticateToken.UserName, authenticateToken.UserDomain, out OpenCifsServerAccount? account) || account == null)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            if (!ValidateAuthenticateTokenTargetInfo(authenticateToken, sessionRecord.ExpectedServerName, sessionRecord.ExpectedUserDomain))
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                password: account.Password,
                userName: authenticateToken.UserName,
                userDomain: authenticateToken.UserDomain,
                serverChallenge: sessionRecord.ServerChallenge,
                ntChallengeResponse: authenticateToken.NtChallengeResponse,
                lmChallengeResponse: authenticateToken.LmChallengeResponse,
                verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet);

            if (!verified || verifiedResponseSet == null)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            NtStatus? legacyCallbackStatus = InvokeAuthenticatedSessionCallback(
                sessionId,
                authenticateToken.UserName,
                authenticateToken.UserDomain,
                sessionRecord.SessionSetupFlavor);

            if (legacyCallbackStatus.HasValue && legacyCallbackStatus.Value != NtStatus.Success)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(legacyCallbackStatus.Value, sessionId, new Smb2SessionSetupResponse());
            }

            sessionRecord.State.Authenticate();
            sessionRecord.SessionBaseKey = verifiedResponseSet.SessionBaseKey;
            sessionRecord.SessionKey = verifiedResponseSet.SessionBaseKey;

            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = Smb2SessionFlags.None,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptCompleted,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm
                })
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            WriteDiagnostic("Legacy NTLM session setup authenticated session " + sessionId + " for '" + authenticateToken.UserDomain + "\\" + authenticateToken.UserName + "'.");
            return CreateSessionSetupResult(NtStatus.Success, sessionId, response);
        }

        private OpenCifsServerSessionSetupResult CompleteStandardSessionSetup(ulong sessionId, Smb2SessionSetupRequest request, ServerSessionRecord sessionRecord)
        {
            if (!TryExtractStandardAuthenticateToken(
                request.SecurityBuffer,
                sessionRecord.SessionSetupFlavor,
                out byte[]? authenticateBytes,
                out NtStatus extractionStatus) || authenticateBytes == null)
            {
                WriteDiagnostic("Standard NTLM session setup failed during authenticate-token extraction with status " + extractionStatus + ".");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(extractionStatus, sessionId, new Smb2SessionSetupResponse());
            }

            NtlmAuthenticateMessage authenticateMessage;

            try
            {
                authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateBytes);
            }
            catch (ProtocolEncodingException)
            {
                WriteDiagnostic("Standard NTLM session setup failed because the authenticate message was malformed.");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.InvalidParameter, sessionId, new Smb2SessionSetupResponse());
            }

            string userName = authenticateMessage.UserName;
            string userDomain = authenticateMessage.DomainName;

            if (string.IsNullOrWhiteSpace(userName))
            {
                WriteDiagnostic("Standard NTLM session setup failed because the authenticate message did not contain a user name.");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            if (!TryGetAccount(userName, userDomain, out OpenCifsServerAccount? account) || account == null)
            {
                WriteDiagnostic("Standard NTLM session setup failed because no registered account matched '" + userDomain + "\\" + userName + "'.");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            if (!ValidateAuthenticateTokenTargetInfo(authenticateMessage.NtChallengeResponse, sessionRecord.ExpectedServerName, sessionRecord.ExpectedUserDomain))
            {
                WriteDiagnostic("Standard NTLM session setup failed because the client target-info AV pairs did not match the issued challenge target.");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                password: account.Password,
                userName: userName,
                userDomain: userDomain,
                serverChallenge: sessionRecord.ServerChallenge,
                ntChallengeResponse: authenticateMessage.NtChallengeResponse,
                lmChallengeResponse: authenticateMessage.LmChallengeResponse,
                verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet);

            if (!verified || verifiedResponseSet == null)
            {
                WriteDiagnostic("Standard NTLM session setup failed because the NTLMv2 challenge-response set did not verify for '" + userDomain + "\\" + userName + "'.");
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
            }

            byte[] sessionKey = verifiedResponseSet.SessionBaseKey;

            if ((authenticateMessage.Flags & NtlmNegotiateFlags.KeyExchange) != 0 &&
                (authenticateMessage.Flags & (NtlmNegotiateFlags.Sign | NtlmNegotiateFlags.Seal)) != 0)
            {
                if (authenticateMessage.EncryptedRandomSessionKey.Length == 0)
                {
                    WriteDiagnostic("Standard NTLM session setup failed because key exchange was negotiated without an encrypted random session key.");
                    CleanupSessionRecord(sessionRecord);
                    _Sessions.Remove(sessionId);
                    return CreateSessionSetupResult(NtStatus.InvalidParameter, sessionId, new Smb2SessionSetupResponse());
                }

                sessionKey = Rc4.Transform(verifiedResponseSet.SessionBaseKey, authenticateMessage.EncryptedRandomSessionKey);
            }

            if (authenticateMessage.MessageIntegrityCodeOffset != 0)
            {
                if (sessionRecord.NegotiateMessage == null || sessionRecord.ChallengeMessage == null || authenticateMessage.MessageIntegrityCode == null)
                {
                    WriteDiagnostic("Standard NTLM session setup failed because the MIC prerequisites were incomplete.");
                    CleanupSessionRecord(sessionRecord);
                    _Sessions.Remove(sessionId);
                    return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
                }

                byte[] authenticateBytesWithZeroMic = (byte[])authenticateBytes.Clone();
                Array.Clear(authenticateBytesWithZeroMic, authenticateMessage.MessageIntegrityCodeOffset, 16);

                if (!NtlmMessageIntegrityCode.Verify(
                    exportedSessionKey: sessionKey,
                    negotiateMessage: sessionRecord.NegotiateMessage,
                    challengeMessage: sessionRecord.ChallengeMessage,
                    authenticateMessageWithZeroMic: authenticateBytesWithZeroMic,
                    messageIntegrityCode: authenticateMessage.MessageIntegrityCode))
                {
                    WriteDiagnostic("Standard NTLM session setup failed because the NTLM MIC did not verify for '" + userDomain + "\\" + userName + "'.");
                    CleanupSessionRecord(sessionRecord);
                    _Sessions.Remove(sessionId);
                    return CreateSessionSetupResult(NtStatus.AccessDenied, sessionId, new Smb2SessionSetupResponse());
                }
            }

            NtStatus? standardCallbackStatus = InvokeAuthenticatedSessionCallback(
                sessionId,
                userName,
                userDomain,
                sessionRecord.SessionSetupFlavor);

            if (standardCallbackStatus.HasValue && standardCallbackStatus.Value != NtStatus.Success)
            {
                CleanupSessionRecord(sessionRecord);
                _Sessions.Remove(sessionId);
                return CreateSessionSetupResult(standardCallbackStatus.Value, sessionId, new Smb2SessionSetupResponse());
            }

            sessionRecord.UserName = userName;
            sessionRecord.UserDomain = userDomain;
            sessionRecord.State.Authenticate();
            sessionRecord.SessionBaseKey = verifiedResponseSet.SessionBaseKey;
            sessionRecord.SessionKey = sessionKey;

            byte[] responseSecurityBuffer = sessionRecord.SessionSetupFlavor == SessionSetupFlavor.SpnegoNtlm
                ? SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptCompleted,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm
                })
                : Array.Empty<byte>();

            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = Smb2SessionFlags.None,
                SecurityBuffer = responseSecurityBuffer
            };
            Smb2SessionSetupResponseValidator.Validate(response);
            WriteDiagnostic("Standard NTLM session setup authenticated session " + sessionId + " for '" + userDomain + "\\" + userName + "'.");
            return CreateSessionSetupResult(NtStatus.Success, sessionId, response);
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

        private NtStatus? InvokeAuthenticatedSessionCallback(ulong sessionId, string userName, string userDomain, SessionSetupFlavor flavor)
        {
            if (Options.RequestCallbacks?.AuthenticatedSessionCallback == null)
            {
                return null;
            }

            return Options.RequestCallbacks.AuthenticatedSessionCallback(new OpenCifsServerAuthenticatedSessionContext
            {
                SessionId = sessionId,
                UserName = userName,
                UserDomain = userDomain,
                AuthenticationFlavor = flavor.ToString()
            });
        }

        private void WriteDiagnostic(string message)
        {
            Options.DiagnosticLogger?.Invoke(message);
        }

        private static OpenCifsServerOperationResult<TResponse> CreateOperationResult<TResponse>(NtStatus status, TResponse response)
            where TResponse : class
        {
            return new OpenCifsServerOperationResult<TResponse>
            {
                Status = status,
                Response = response
            };
        }

        private ushort DetermineCreditsToGrant(ushort requestedCredits)
        {
            int remainingCapacity = Options.MaximumCredits - _Credits.AvailableCredits;
            int boundedGrant = Math.Clamp(requestedCredits, 1, Math.Max(1, remainingCapacity));
            return unchecked((ushort)boundedGrant);
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

            if (_NegotiatedDialect == null || _NegotiatedDialect.Value < SmbDialect.Smb21)
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
                ulong messageId = startingMessageId + unchecked((ulong)index);

                if (!_AvailableMessageIds.Remove(messageId))
                {
                    throw new ProtocolValidationException("The SMB2 request message identifier is outside the current server credit window.", argumentName);
                }
            }
        }

        private static uint GetImplementedReadWriteSizeForDialect(SmbDialect dialect)
        {
            return Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect);
        }

        private uint GetImplementedReadWriteSizeForCurrentDialect()
        {
            return GetImplementedReadWriteSizeForDialect(_NegotiatedDialect ?? SmbDialect.Smb2002);
        }

        private void ValidateReadWriteCreditCharge(Smb2Header requestHeader, uint length, string argumentName)
        {
            ushort expectedCredits = Smb2CreditChargeHelper.GetRequiredReadWriteCredits(_NegotiatedDialect, length);

            if (requestHeader.CreditCharge == 0)
            {
                if (expectedCredits > 1)
                {
                    throw new ProtocolValidationException("The SMB2 request CreditCharge is too small for the bounded large-I/O length.", argumentName);
                }

                return;
            }

            if (requestHeader.CreditCharge < expectedCredits)
            {
                throw new ProtocolValidationException("The SMB2 request CreditCharge is too small for the bounded large-I/O length.", argumentName);
            }
        }

        private void GrantCredits(ushort creditCount)
        {
            _Credits.Grant(creditCount);

            for (ushort index = 0; index < creditCount; index++)
            {
                _AvailableMessageIds.Add(_NextMessageIdToGrant);
                _NextMessageIdToGrant++;
            }
        }

        private RequestState GetPendingRequest(ulong messageId)
        {
            if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState))
            {
                throw new ProtocolValidationException("The SMB2 response header does not match any accepted request on this host.", nameof(messageId));
            }

            return requestState;
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
            if (_Sessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) &&
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

        private static bool IsCreateContextName(Smb2CreateContext createContext, byte b0, byte b1, byte b2, byte b3)
        {
            return createContext.Name.Length == 4 &&
                createContext.Name[0] == b0 &&
                createContext.Name[1] == b1 &&
                createContext.Name[2] == b2 &&
                createContext.Name[3] == b3;
        }

        private bool ShouldRequireSignedRequest(Smb2Header requestHeader, out byte[]? signingKey)
        {
            signingKey = null;

            if (requestHeader.SessionId == 0 ||
                requestHeader.Command == Smb2Command.Negotiate ||
                requestHeader.Command == Smb2Command.SessionSetup)
            {
                return false;
            }

            if (!TryGetSessionSigningKey(requestHeader.SessionId, out signingKey))
            {
                return false;
            }

            return Options.RequireSigning || IsSessionSigningRequired();
        }

        private bool IsSessionSigningRequired()
        {
            return (_NegotiatedServerSecurityMode & Smb2SecurityMode.SigningRequired) != 0 ||
                (_NegotiatedClientSecurityMode & Smb2SecurityMode.SigningRequired) != 0;
        }

        private Smb2Header CreateOplockBreakNotificationHeader(ServerOpenRecord openRecord)
        {
            Smb2HeaderFlags flags = Smb2HeaderFlags.ServerToRedir;

            if (TryGetSessionSigningKey(openRecord.SessionId, out byte[]? _) &&
                (Options.RequireSigning || IsSessionSigningRequired()))
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
                MessageId = UInt64.MaxValue,
                TreeId = openRecord.TreeId,
                SessionId = openRecord.SessionId,
                Signature = new byte[16]
            };
            Smb2HeaderValidator.Validate(header);
            return header;
        }

        private Smb2Header CreateInterimAsyncResponseHeader(Smb2Header requestHeader)
        {
            RequestState requestState = GetPendingRequest(requestHeader.MessageId);

            if (requestState.Command != requestHeader.Command)
            {
                throw new ProtocolValidationException("The accepted SMB2 request does not match the interim async response command.", nameof(requestHeader));
            }

            ushort creditsGranted = DetermineCreditsToGrant(requestHeader.CreditRequest);
            GrantCredits(creditsGranted);

            ulong asyncId = _NextAsyncId++;
            requestState.MarkAsync(asyncId);

            Smb2Header responseHeader = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Pending,
                Command = requestHeader.Command,
                CreditRequest = creditsGranted,
                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand | (requestHeader.Flags & Smb2HeaderFlags.Signed),
                NextCommand = 0,
                MessageId = requestHeader.MessageId,
                AsyncId = asyncId,
                SessionId = requestHeader.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(responseHeader);
            return responseHeader;
        }

        private OpenCifsServerAsyncResponse CreateChangeNotifyErrorResponse(Smb2Header requestHeader, NtStatus status, ulong sessionId, uint treeId)
        {
            Smb2ErrorResponse errorResponse = new Smb2ErrorResponse();
            Smb2ErrorResponseValidator.Validate(errorResponse);
            return new OpenCifsServerAsyncResponse
            {
                Header = CreateResponseHeader(requestHeader, status, sessionId: sessionId, treeId: treeId),
                Payload = errorResponse.ToByteArray()
            };
        }

        private Smb2CompoundPacketEntry HandleCompoundRequestEntry(Smb2CompoundPacketEntry requestEntry)
        {
            Smb2Header requestHeader = requestEntry.Header;
            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimRequestPayload(requestHeader.Command, requestEntry.Payload);

            switch (requestHeader.Command)
            {
                case Smb2Command.Negotiate:
                    Smb2NegotiateRequest negotiateRequest = Smb2NegotiateRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Negotiate);
                    Smb2NegotiateResponse negotiateResponse = HandleNegotiate(negotiateRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, NtStatus.Success),
                        negotiateResponse.ToByteArray());
                case Smb2Command.SessionSetup:
                    Smb2SessionSetupRequest sessionSetupRequest = Smb2SessionSetupRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.SessionSetup, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerSessionSetupResult sessionSetupResult = HandleSessionSetup(requestHeader.SessionId, sessionSetupRequest);
                    Smb2HeaderFlags sessionSetupResponseFlags = sessionSetupResult.Status == NtStatus.Success
                        ? Smb2HeaderFlags.Signed
                        : Smb2HeaderFlags.None;
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, sessionSetupResult.Status, sessionId: sessionSetupResult.SessionId, additionalFlags: sessionSetupResponseFlags),
                        sessionSetupResult.Response.ToByteArray());
                case Smb2Command.Logoff:
                    Smb2LogoffRequest logoffRequest = Smb2LogoffRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Logoff, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = HandleLogoff(requestHeader.SessionId, logoffRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, logoffResult.Status, sessionId: requestHeader.SessionId),
                        logoffResult.Response.ToByteArray());
                case Smb2Command.Echo:
                    Smb2EchoRequest echoRequest = Smb2EchoRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Echo, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = HandleEcho(requestHeader.SessionId, echoRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, echoResult.Status, sessionId: requestHeader.SessionId),
                        echoResult.Response.ToByteArray());
                case Smb2Command.TreeConnect:
                    Smb2TreeConnectRequest treeConnectRequest = Smb2TreeConnectRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.TreeConnect, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerTreeConnectResult treeConnectResult = HandleTreeConnect(requestHeader.SessionId, treeConnectRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, treeConnectResult.Status, sessionId: requestHeader.SessionId, treeId: treeConnectResult.TreeId),
                        treeConnectResult.Response.ToByteArray());
                case Smb2Command.TreeDisconnect:
                    Smb2TreeDisconnectRequest treeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.TreeDisconnect, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = HandleTreeDisconnect(requestHeader.SessionId, requestHeader.TreeId, treeDisconnectRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, treeDisconnectResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        treeDisconnectResult.Response.ToByteArray());
                case Smb2Command.Create:
                    Smb2CreateRequest createRequest = Smb2CreateRequest.ReadFrom(trimmedPayload);
                    WriteDiagnostic(
                        "Create request received for session " +
                        requestHeader.SessionId.ToString() +
                        ", tree " +
                        requestHeader.TreeId.ToString() +
                        ", name '" +
                        createRequest.Name +
                        "', disposition " +
                        createRequest.CreateDisposition +
                        ", options " +
                        createRequest.CreateOptions +
                        ", desired access 0x" +
                        createRequest.DesiredAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                        ", share access 0x" +
                        createRequest.ShareAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                        ".");
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Create, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2CreateResponse> createResult = HandleCreate(requestHeader.SessionId, requestHeader.TreeId, createRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, createResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        createResult.Response.ToByteArray());
                case Smb2Command.Read:
                    Smb2ReadRequest readRequest = Smb2ReadRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Read, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    ValidateReadWriteCreditCharge(requestHeader, readRequest.Length, nameof(requestHeader));
                    OpenCifsServerOperationResult<Smb2ReadResponse> readResult = HandleRead(requestHeader.SessionId, requestHeader.TreeId, readRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, readResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        readResult.Response.ToByteArray());
                case Smb2Command.Write:
                    Smb2WriteRequest writeRequest = Smb2WriteRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Write, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    ValidateReadWriteCreditCharge(requestHeader, checked((uint)writeRequest.DataBuffer.Length), nameof(requestHeader));
                    OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = HandleWrite(requestHeader.SessionId, requestHeader.TreeId, writeRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, writeResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        writeResult.Response.ToByteArray());
                case Smb2Command.Flush:
                    Smb2FlushRequest flushRequest = Smb2FlushRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Flush, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = HandleFlush(requestHeader.SessionId, requestHeader.TreeId, flushRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, flushResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        flushResult.Response.ToByteArray());
                case Smb2Command.Close:
                    Smb2CloseRequest closeRequest = Smb2CloseRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Close, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = HandleClose(requestHeader.SessionId, requestHeader.TreeId, closeRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, closeResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        closeResult.Response.ToByteArray());
                case Smb2Command.Lock:
                    Smb2LockRequest lockRequest = Smb2LockRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Lock, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2LockResponse> lockResult = HandleLock(requestHeader.SessionId, requestHeader.TreeId, lockRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, lockResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        lockResult.Response.ToByteArray());
                case Smb2Command.OplockBreak:
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.OplockBreak, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    ushort breakStructureSize = new LittleEndianReader(trimmedPayload).ReadUInt16();

                    if (breakStructureSize == 24)
                    {
                        Smb2OplockBreakAcknowledgment oplockBreakAcknowledgment = Smb2OplockBreakAcknowledgment.ReadFrom(trimmedPayload);
                        OpenCifsServerOperationResult<Smb2OplockBreakResponse> oplockBreakResult = HandleOplockBreakAcknowledgment(requestHeader.SessionId, requestHeader.TreeId, oplockBreakAcknowledgment);
                        return new Smb2CompoundPacketEntry(
                            CreateResponseHeader(requestHeader, oplockBreakResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                            oplockBreakResult.Response.ToByteArray());
                    }

                    if (breakStructureSize == 36)
                    {
                        Smb2LeaseBreakAcknowledgment leaseBreakAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(trimmedPayload);
                        OpenCifsServerOperationResult<Smb2LeaseBreakResponse> leaseBreakResult = HandleLeaseBreakAcknowledgment(requestHeader.SessionId, requestHeader.TreeId, leaseBreakAcknowledgment);
                        return new Smb2CompoundPacketEntry(
                            CreateResponseHeader(requestHeader, leaseBreakResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                            leaseBreakResult.Response.ToByteArray());
                    }

                    throw new ProtocolValidationException("The SMB2 OPLOCK_BREAK request structure size is not supported in the current SMB 2.1 slice.", nameof(trimmedPayload));
                case Smb2Command.Ioctl:
                    Smb2IoctlRequest ioctlRequest = Smb2IoctlRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Ioctl, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = HandleIoctl(requestHeader.SessionId, requestHeader.TreeId, ioctlRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, ioctlResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        ioctlResult.Response.ToByteArray());
                case Smb2Command.QueryInfo:
                    Smb2QueryInfoRequest queryInfoRequest = Smb2QueryInfoRequest.ReadFrom(trimmedPayload);
                    WriteDiagnostic(
                        "Query-info request received for session " +
                        requestHeader.SessionId.ToString() +
                        ", tree " +
                        requestHeader.TreeId.ToString() +
                        ", info type " +
                        queryInfoRequest.InfoType +
                        ", file class " +
                        FormatQueryInfoClass(queryInfoRequest) +
                        ", output length " +
                        queryInfoRequest.OutputBufferLength.ToString() +
                        ", additional information 0x" +
                        queryInfoRequest.AdditionalInformation.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                        ", flags 0x" +
                        queryInfoRequest.Flags.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                        ".");
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.QueryInfo, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2QueryInfoResponse> queryInfoResult = HandleQueryInfo(requestHeader.SessionId, requestHeader.TreeId, queryInfoRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, queryInfoResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        queryInfoResult.Response.ToByteArray());
                case Smb2Command.SetInfo:
                    Smb2SetInfoRequest setInfoRequest = Smb2SetInfoRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.SetInfo, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2SetInfoResponse> setInfoResult = HandleSetInfo(requestHeader.SessionId, requestHeader.TreeId, setInfoRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, setInfoResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        setInfoResult.Response.ToByteArray());
                case Smb2Command.QueryDirectory:
                    Smb2QueryDirectoryRequest queryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(trimmedPayload);
                    ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.QueryDirectory, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = HandleQueryDirectory(requestHeader.SessionId, requestHeader.TreeId, queryDirectoryRequest);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(requestHeader, queryDirectoryResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        queryDirectoryResult.Response.ToByteArray());
                default:
                    throw new ProtocolValidationException("The SMB2 command is not supported by the current compounded-request surface.", nameof(requestEntry));
            }
        }

        private Smb2CompoundPacket HandleRelatedCompoundRequestPacket(Smb2CompoundPacket requestPacket)
        {
            List<Smb2CompoundPacketEntry> responseEntries = new List<Smb2CompoundPacketEntry>(requestPacket.Entries.Count);
            RelatedCompoundContext context = new RelatedCompoundContext();

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                responseEntries.Add(HandleRelatedCompoundRequestEntry(requestPacket.Entries[index], context, isFirstEntry: index == 0));
            }

            return new Smb2CompoundPacket(responseEntries);
        }

        private Smb2CompoundPacketEntry HandleRelatedCompoundRequestEntry(Smb2CompoundPacketEntry requestEntry, RelatedCompoundContext context, bool isFirstEntry)
        {
            Smb2Header requestHeader = requestEntry.Header;
            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimRequestPayload(requestHeader.Command, requestEntry.Payload);
            Smb2Header effectiveHeader = CloneHeader(requestHeader);
            Smb2HeaderFlags responseFlags = isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations;

            WriteDiagnostic(
                "Dispatching related request entry: command=" +
                requestHeader.Command +
                ", messageId=" +
                requestHeader.MessageId +
                ", sessionId=" +
                requestHeader.SessionId +
                ", treeId=" +
                requestHeader.TreeId +
                ", flags=" +
                requestHeader.Flags +
                ", firstEntry=" +
                isFirstEntry +
                ".");

            if (!isFirstEntry)
            {
                effectiveHeader.Flags = Smb2HeaderFlags.RelatedOperations;

                if (CommandRequiresSessionId(requestHeader.Command))
                {
                    if (!context.HasSessionId)
                    {
                        return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, NtStatus.InvalidParameter, context, responseFlags);
                    }

                    effectiveHeader.SessionId = context.SessionId;
                }

                if (CommandRequiresTreeId(requestHeader.Command))
                {
                    if (!context.HasTreeId)
                    {
                        return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, NtStatus.InvalidParameter, context, responseFlags);
                    }

                    effectiveHeader.TreeId = context.TreeId;
                }

                if (CommandRequiresFileId(requestHeader.Command) && context.PreviousStatus != NtStatus.Success && (context.HasFileId || context.PreviousCouldGenerateFileId))
                {
                    return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, context.PreviousStatus, context, responseFlags);
                }
            }

            switch (requestHeader.Command)
            {
                case Smb2Command.TreeConnect:
                {
                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.TreeConnect, expectedSessionId: effectiveHeader.SessionId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2TreeConnectRequest treeConnectRequest = Smb2TreeConnectRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerTreeConnectResult treeConnectResult = HandleTreeConnect(effectiveHeader.SessionId, treeConnectRequest);
                    context.Update(
                        status: treeConnectResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: treeConnectResult.TreeId,
                        hasTreeId: treeConnectResult.TreeId != 0,
                        persistentFileId: 0,
                        volatileFileId: 0,
                        hasFileId: false,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, treeConnectResult.Status, sessionId: effectiveHeader.SessionId, treeId: treeConnectResult.TreeId, additionalFlags: responseFlags),
                        treeConnectResult.Response.ToByteArray());
                }
                case Smb2Command.TreeDisconnect:
                {
                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.TreeDisconnect, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2TreeDisconnectRequest treeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = HandleTreeDisconnect(effectiveHeader.SessionId, effectiveHeader.TreeId, treeDisconnectRequest);
                    context.Update(
                        status: treeDisconnectResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: true,
                        persistentFileId: 0,
                        volatileFileId: 0,
                        hasFileId: false,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, treeDisconnectResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        treeDisconnectResult.Response.ToByteArray());
                }
                case Smb2Command.Create:
                {
                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Create, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2CreateRequest createRequest = Smb2CreateRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerOperationResult<Smb2CreateResponse> createResult = HandleCreate(effectiveHeader.SessionId, effectiveHeader.TreeId, createRequest);
                    bool hasGeneratedFileId = createResult.Status == NtStatus.Success && (createResult.Response.PersistentFileId != 0 || createResult.Response.VolatileFileId != 0);
                    context.Update(
                        status: createResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: createResult.Response.PersistentFileId,
                        volatileFileId: createResult.Response.VolatileFileId,
                        hasFileId: hasGeneratedFileId,
                        previousCouldGenerateFileId: true);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, createResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        createResult.Response.ToByteArray());
                }
                case Smb2Command.Write:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Write, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2WriteRequest writeRequest = Smb2WriteRequest.ReadFrom(trimmedPayload);
                    ValidateReadWriteCreditCharge(effectiveHeader, checked((uint)writeRequest.DataBuffer.Length), nameof(effectiveHeader));
                    writeRequest.PersistentFileId = persistentFileId;
                    writeRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = HandleWrite(effectiveHeader.SessionId, effectiveHeader.TreeId, writeRequest);
                    context.Update(
                        status: writeResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, writeResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        writeResult.Response.ToByteArray());
                }
                case Smb2Command.Flush:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Flush, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2FlushRequest flushRequest = Smb2FlushRequest.ReadFrom(trimmedPayload);
                    flushRequest.PersistentFileId = persistentFileId;
                    flushRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = HandleFlush(effectiveHeader.SessionId, effectiveHeader.TreeId, flushRequest);
                    context.Update(
                        status: flushResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, flushResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        flushResult.Response.ToByteArray());
                }
                case Smb2Command.Read:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Read, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2ReadRequest readRequest = Smb2ReadRequest.ReadFrom(trimmedPayload);
                    ValidateReadWriteCreditCharge(effectiveHeader, readRequest.Length, nameof(effectiveHeader));
                    readRequest.PersistentFileId = persistentFileId;
                    readRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2ReadResponse> readResult = HandleRead(effectiveHeader.SessionId, effectiveHeader.TreeId, readRequest);
                    context.Update(
                        status: readResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, readResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        readResult.Response.ToByteArray());
                }
                case Smb2Command.Close:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Close, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2CloseRequest closeRequest = Smb2CloseRequest.ReadFrom(trimmedPayload);
                    closeRequest.PersistentFileId = persistentFileId;
                    closeRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = HandleClose(effectiveHeader.SessionId, effectiveHeader.TreeId, closeRequest);
                    context.Update(
                        status: closeResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, closeResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        closeResult.Response.ToByteArray());
                }
                case Smb2Command.Lock:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Lock, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2LockRequest lockRequest = Smb2LockRequest.ReadFrom(trimmedPayload);
                    lockRequest.PersistentFileId = persistentFileId;
                    lockRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2LockResponse> lockResult = HandleLock(effectiveHeader.SessionId, effectiveHeader.TreeId, lockRequest);
                    context.Update(
                        status: lockResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, lockResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        lockResult.Response.ToByteArray());
                }
                case Smb2Command.QueryInfo:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.QueryInfo, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2QueryInfoRequest queryInfoRequest = Smb2QueryInfoRequest.ReadFrom(trimmedPayload);
                    queryInfoRequest.PersistentFileId = persistentFileId;
                    queryInfoRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2QueryInfoResponse> queryInfoResult = HandleQueryInfo(effectiveHeader.SessionId, effectiveHeader.TreeId, queryInfoRequest);
                    context.Update(
                        status: queryInfoResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, queryInfoResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        queryInfoResult.Response.ToByteArray());
                }
                case Smb2Command.SetInfo:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.SetInfo, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2SetInfoRequest setInfoRequest = Smb2SetInfoRequest.ReadFrom(trimmedPayload);
                    setInfoRequest.PersistentFileId = persistentFileId;
                    setInfoRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2SetInfoResponse> setInfoResult = HandleSetInfo(effectiveHeader.SessionId, effectiveHeader.TreeId, setInfoRequest);
                    context.Update(
                        status: setInfoResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, setInfoResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        setInfoResult.Response.ToByteArray());
                }
                case Smb2Command.QueryDirectory:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.QueryDirectory, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2QueryDirectoryRequest queryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(trimmedPayload);
                    queryDirectoryRequest.PersistentFileId = persistentFileId;
                    queryDirectoryRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = HandleQueryDirectory(effectiveHeader.SessionId, effectiveHeader.TreeId, queryDirectoryRequest);
                    context.Update(
                        status: queryDirectoryResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, queryDirectoryResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        queryDirectoryResult.Response.ToByteArray());
                }
                case Smb2Command.Ioctl:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, responseFlags))
                    {
                        return errorEntry!;
                    }

                    ValidateAndAcceptRequestHeader(effectiveHeader, Smb2Command.Ioctl, expectedSessionId: effectiveHeader.SessionId, expectedTreeId: effectiveHeader.TreeId, allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2IoctlRequest ioctlRequest = Smb2IoctlRequest.ReadFrom(trimmedPayload);

                    if (IsWildcardIoctlFileId(ioctlRequest.PersistentFileId, ioctlRequest.VolatileFileId))
                    {
                        Smb2IoctlResponse invalidIoctlResponse = new Smb2IoctlResponse
                        {
                            CtlCode = ioctlRequest.CtlCode,
                            PersistentFileId = persistentFileId,
                            VolatileFileId = volatileFileId,
                            InputBuffer = Array.Empty<byte>(),
                            OutputBuffer = Array.Empty<byte>(),
                            Flags = 0
                        };
                        Smb2IoctlResponseValidator.Validate(invalidIoctlResponse);
                        context.Update(
                            status: NtStatus.InvalidParameter,
                            sessionId: effectiveHeader.SessionId,
                            hasSessionId: effectiveHeader.SessionId != 0,
                            treeId: effectiveHeader.TreeId,
                            hasTreeId: effectiveHeader.TreeId != 0,
                            persistentFileId: persistentFileId,
                            volatileFileId: volatileFileId,
                            hasFileId: true,
                            previousCouldGenerateFileId: false);
                        return new Smb2CompoundPacketEntry(
                            CreateResponseHeader(effectiveHeader, NtStatus.InvalidParameter, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                            invalidIoctlResponse.ToByteArray());
                    }

                    ioctlRequest.PersistentFileId = persistentFileId;
                    ioctlRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = HandleIoctl(effectiveHeader.SessionId, effectiveHeader.TreeId, ioctlRequest);
                    context.Update(
                        status: ioctlResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        CreateResponseHeader(effectiveHeader, ioctlResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        ioctlResult.Response.ToByteArray());
                }
                default:
                    throw new ProtocolValidationException("Related SMB2 compound request chains are only implemented for the current synchronous tree, file, metadata, locking, and open-scoped IOCTL surface.", nameof(requestEntry));
            }
        }

        private static bool CommandRequiresSessionId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.TreeConnect:
                case Smb2Command.TreeDisconnect:
                case Smb2Command.Create:
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                case Smb2Command.Echo:
                case Smb2Command.Logoff:
                    return true;
                default:
                    return false;
            }
        }

        private static bool CommandRequiresTreeId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.TreeDisconnect:
                case Smb2Command.Create:
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.Ioctl:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                    return true;
                default:
                    return false;
            }
        }

        private static bool CommandRequiresFileId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.Ioctl:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                    return true;
                default:
                    return false;
            }
        }

        private static Smb2Header CloneHeader(Smb2Header header)
        {
            return new Smb2Header
            {
                CreditCharge = header.CreditCharge,
                Status = header.Status,
                Command = header.Command,
                CreditRequest = header.CreditRequest,
                Flags = header.Flags,
                NextCommand = header.NextCommand,
                MessageId = header.MessageId,
                ProcessId = header.ProcessId,
                TreeId = header.TreeId,
                SessionId = header.SessionId,
                Signature = (byte[])header.Signature.Clone()
            };
        }

        private bool PrepareRelatedFileId(Smb2Header effectiveHeader, Smb2Command command, RelatedCompoundContext context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry? errorEntry, Smb2HeaderFlags responseFlags)
        {
            if (!context.HasFileId)
            {
                NtStatus status = context.PreviousStatus != NtStatus.Success && (context.HasFileId || context.PreviousCouldGenerateFileId)
                    ? context.PreviousStatus
                    : NtStatus.InvalidHandle;
                errorEntry = CreateRelatedErrorResponseEntry(effectiveHeader, command, status, context, responseFlags);
                persistentFileId = 0;
                volatileFileId = 0;
                return false;
            }

            persistentFileId = context.PersistentFileId;
            volatileFileId = context.VolatileFileId;
            errorEntry = null;
            return true;
        }

        private Smb2CompoundPacketEntry CreateRelatedErrorResponseEntry(Smb2Header effectiveHeader, Smb2Command command, NtStatus status, RelatedCompoundContext context, Smb2HeaderFlags responseFlags)
        {
            ValidateAndAcceptRequestHeader(
                effectiveHeader,
                command,
                expectedSessionId: effectiveHeader.SessionId,
                expectedTreeId: effectiveHeader.TreeId,
                allowedRequestFlags: responseFlags == Smb2HeaderFlags.None ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);

            byte[] payload = CreateDefaultResponsePayload(command);
            return new Smb2CompoundPacketEntry(
                CreateResponseHeader(
                    effectiveHeader,
                    status,
                    sessionId: effectiveHeader.SessionId != 0 ? effectiveHeader.SessionId : context.SessionId,
                    treeId: effectiveHeader.TreeId != 0 ? effectiveHeader.TreeId : context.TreeId,
                    additionalFlags: responseFlags),
                payload);
        }

        private static byte[] CreateDefaultResponsePayload(Smb2Command command)
        {
            if (!TryCreateDefaultResponsePayload(command, out byte[]? payload) || payload == null)
            {
                throw new ProtocolValidationException("No default error payload is available for the specified SMB2 command.", nameof(command));
            }

            return payload;
        }

        private static bool TryCreateDefaultResponsePayload(Smb2Command command, out byte[]? payload)
        {
            switch (command)
            {
                case Smb2Command.SessionSetup:
                    payload = new Smb2SessionSetupResponse().ToByteArray();
                    return true;
                case Smb2Command.Logoff:
                    payload = new Smb2LogoffResponse().ToByteArray();
                    return true;
                case Smb2Command.Echo:
                    payload = new Smb2EchoResponse().ToByteArray();
                    return true;
                case Smb2Command.TreeConnect:
                    payload = new Smb2TreeConnectResponse().ToByteArray();
                    return true;
                case Smb2Command.TreeDisconnect:
                    payload = new Smb2TreeDisconnectResponse().ToByteArray();
                    return true;
                case Smb2Command.Create:
                    payload = new Smb2CreateResponse().ToByteArray();
                    return true;
                case Smb2Command.Read:
                    payload = new Smb2ReadResponse().ToByteArray();
                    return true;
                case Smb2Command.Write:
                    payload = new Smb2WriteResponse().ToByteArray();
                    return true;
                case Smb2Command.Flush:
                    payload = new Smb2FlushResponse().ToByteArray();
                    return true;
                case Smb2Command.Close:
                    payload = new Smb2CloseResponse().ToByteArray();
                    return true;
                case Smb2Command.Lock:
                    payload = new Smb2LockResponse().ToByteArray();
                    return true;
                case Smb2Command.Ioctl:
                    payload = new Smb2IoctlResponse().ToByteArray();
                    return true;
                case Smb2Command.QueryInfo:
                    payload = new Smb2QueryInfoResponse().ToByteArray();
                    return true;
                case Smb2Command.SetInfo:
                    payload = new Smb2SetInfoResponse().ToByteArray();
                    return true;
                case Smb2Command.QueryDirectory:
                    payload = new Smb2QueryDirectoryResponse().ToByteArray();
                    return true;
                default:
                    payload = null;
                    return false;
            }
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

            if ((requestHeader.Flags & ~(Smb2HeaderFlags.AsyncCommand | Smb2HeaderFlags.Signed)) != Smb2HeaderFlags.None)
            {
                throw new ProtocolValidationException("The bounded SMB2 cancel request surface only supports signed or unsigned synchronous or async cancel headers.", nameof(requestHeader));
            }

            if ((requestHeader.Flags & Smb2HeaderFlags.AsyncCommand) != 0 && requestHeader.AsyncId == 0)
            {
                throw new ProtocolValidationException("Asynchronous SMB2 cancel headers must carry a non-zero AsyncId.", nameof(requestHeader));
            }
        }

        private bool TryGetAuthenticatedTree(ulong sessionId, uint treeId, out ServerSessionRecord? sessionRecord)
        {
            return TryGetAuthenticatedTree(sessionId, treeId, out sessionRecord, out _);
        }

        private bool TryGetAuthenticatedTree(ulong sessionId, uint treeId, out ServerSessionRecord? sessionRecord, out ServerTreeRecord? treeRecord)
        {
            if (!_Sessions.TryGetValue(sessionId, out sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                sessionRecord = null;
                treeRecord = null;
                return false;
            }

            return sessionRecord.Trees.TryGetValue(treeId, out treeRecord);
        }

        private static bool TryGetOpen(ServerSessionRecord sessionRecord, uint treeId, ulong persistentFileId, ulong volatileFileId, out ServerOpenRecord? openRecord)
        {
            if (!sessionRecord.Opens.TryGetValue(volatileFileId, out openRecord))
            {
                openRecord = null;
                return false;
            }

            return openRecord.State.PersistentFileId == persistentFileId && openRecord.TreeId == treeId;
        }

        private static bool TryGetOpenByLeaseKey(ServerSessionRecord sessionRecord, uint treeId, byte[] leaseKey, out ServerOpenRecord? openRecord)
        {
            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            foreach (ServerOpenRecord candidate in sessionRecord.Opens.Values)
            {
                if (candidate.TreeId == treeId &&
                    candidate.LeaseRecord != null &&
                    candidate.LeaseRecord.LeaseKey.AsSpan().SequenceEqual(leaseKey))
                {
                    openRecord = candidate;
                    return true;
                }
            }

            openRecord = null;
            return false;
        }

        private void UpdateLeaseStateForTrackedOpens(OpenCifsServerLeaseRecord leaseRecord)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (!ReferenceEquals(openRecord.LeaseRecord, leaseRecord))
                        {
                            continue;
                        }

                        openRecord.State.SetLeaseState(leaseRecord.LeaseState);
                    }
                }
            }
        }

        private void CleanupSessionRecord(ServerSessionRecord sessionRecord)
        {
            List<ulong> volatileFileIds = new List<ulong>(sessionRecord.Opens.Keys);

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                CloseOpenRecord(sessionRecord, volatileFileIds[index]);
            }

            foreach (ServerTreeRecord treeRecord in sessionRecord.Trees.Values)
            {
                treeRecord.State.Dispose();
            }

            sessionRecord.Trees.Clear();
            sessionRecord.State.Dispose();
        }

        private static Smb2IoctlResponse CreateIoctlResponse(Smb2IoctlRequest request)
        {
            Smb2IoctlResponse response = new Smb2IoctlResponse
            {
                CtlCode = request.CtlCode,
                PersistentFileId = request.PersistentFileId,
                VolatileFileId = request.VolatileFileId,
                InputBuffer = Array.Empty<byte>(),
                OutputBuffer = Array.Empty<byte>(),
                Flags = 0
            };

            Smb2IoctlResponseValidator.Validate(response);
            return response;
        }

        private static OpenCifsServerOperationResult<Smb2IoctlResponse> HandleEnumerateSnapshotsIoctl(Smb2IoctlRequest request, ServerOpenRecord openRecord)
        {
            if (request.InputBuffer.Length != 0 || request.MaxInputResponse != 0)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, CreateIoctlResponse(request));
            }

            if (request.MaxOutputResponse < 16)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, CreateIoctlResponse(request));
            }

            SrvSnapshotArray snapshotArray = new SrvSnapshotArray
            {
                NumberOfSnapshots = 0,
                Snapshots = Array.Empty<string>()
            };

            Smb2IoctlResponse response = new Smb2IoctlResponse
            {
                CtlCode = request.CtlCode,
                PersistentFileId = openRecord.State.PersistentFileId,
                VolatileFileId = openRecord.State.VolatileFileId,
                InputBuffer = Array.Empty<byte>(),
                OutputBuffer = snapshotArray.ToByteArray(),
                Flags = 0
            };

            Smb2IoctlResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        private OpenCifsServerOperationResult<Smb2IoctlResponse> HandleValidateNegotiateInfoIoctl(Smb2IoctlRequest request)
        {
            Smb2IoctlResponse defaultResponse = CreateIoctlResponse(request);

            if (_NegotiatedDialect == null)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (request.MaxOutputResponse < 24)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            ValidateNegotiateInfoRequest validateRequest;

            try
            {
                validateRequest = ValidateNegotiateInfoRequest.ReadFrom(request.InputBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (validateRequest.ClientGuid != _NegotiatedClientGuid ||
                validateRequest.SecurityMode != _NegotiatedClientSecurityMode ||
                validateRequest.Capabilities != _NegotiatedClientCapabilities ||
                !TrySelectRequestedValidateDialect(validateRequest.Dialects, out SmbDialect matchedDialect) ||
                matchedDialect != _NegotiatedDialect.Value)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, defaultResponse);
            }

            ValidateNegotiateInfoResponse validateResponse = new ValidateNegotiateInfoResponse
            {
                Capabilities = _NegotiatedServerCapabilities,
                ServerGuid = ServerGuid,
                SecurityMode = _NegotiatedServerSecurityMode,
                Dialect = _NegotiatedDialect.Value
            };

            Smb2IoctlResponse response = new Smb2IoctlResponse
            {
                CtlCode = request.CtlCode,
                PersistentFileId = WildcardIoctlFileId,
                VolatileFileId = WildcardIoctlFileId,
                InputBuffer = Array.Empty<byte>(),
                OutputBuffer = validateResponse.ToByteArray(),
                Flags = 0
            };

            Smb2IoctlResponseValidator.Validate(response);
            return CreateOperationResult(NtStatus.Success, response);
        }

        private static bool IsConnectionScopedFsctl(uint ctlCode)
        {
            switch ((FsctlCode)ctlCode)
            {
                case FsctlCode.DfsGetReferrals:
                case FsctlCode.DfsGetReferralsEx:
                case FsctlCode.QueryNetworkInterfaceInfo:
                case FsctlCode.ValidateNegotiateInfo:
                case FsctlCode.PipeWait:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsWildcardIoctlFileId(ulong persistentFileId, ulong volatileFileId)
        {
            return persistentFileId == WildcardIoctlFileId && volatileFileId == WildcardIoctlFileId;
        }

        private bool TrySelectRequestedValidateDialect(IReadOnlyList<SmbDialect> requestDialects, out SmbDialect matchedDialect)
        {
            matchedDialect = default;

            if (_NegotiatedClientDialects.Length == 0 || _NegotiatedDialect == null)
            {
                return false;
            }

            SmbDialect[] requestDialectArray = new SmbDialect[requestDialects.Count];

            for (int index = 0; index < requestDialects.Count; index++)
            {
                requestDialectArray[index] = requestDialects[index];
            }

            return SmbDialectCatalog.TrySelectHighestCommonSmb2Dialect(
                clientDialects: requestDialectArray,
                minimumServerDialect: _NegotiatedDialect.Value,
                maximumServerDialect: _NegotiatedDialect.Value,
                negotiatedDialect: out matchedDialect);
        }

        private void CleanupTreeOpenRecords(ServerSessionRecord sessionRecord, uint treeId)
        {
            List<ulong> volatileFileIds = new List<ulong>();

            foreach (KeyValuePair<ulong, ServerOpenRecord> entry in sessionRecord.Opens)
            {
                if (entry.Value.TreeId == treeId)
                {
                    volatileFileIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                CloseOpenRecord(sessionRecord, volatileFileIds[index]);
            }
        }

        private void CloseOpenRecord(ServerSessionRecord sessionRecord, ulong volatileFileId)
        {
            if (sessionRecord.Opens.TryGetValue(volatileFileId, out ServerOpenRecord? openRecord))
            {
                string fullPath = openRecord.FullPath;
                bool deletePending = openRecord.State.IsDeletePending;
                bool isDirectory = openRecord.IsDirectory;
                OpenCifsServerLeaseRecord? leaseRecord = openRecord.LeaseRecord;
                QueueCancelledChangeNotifyResponsesForOpen(volatileFileId);
                openRecord.Dispose();
                sessionRecord.Opens.Remove(volatileFileId);

                if (leaseRecord != null)
                {
                    leaseRecord.OpenCount = Math.Max(0, leaseRecord.OpenCount - 1);
                    _SharedState.RemoveLeaseRecordIfUnused(leaseRecord);
                }

                if (deletePending && !HasOpenRecordsForPath(fullPath))
                {
                    if (DeleteBackingObjectIfPresent(openRecord.Backend, fullPath))
                    {
                        PublishNameChangeNotification(fullPath, isDirectory, FileNotifyAction.Removed);
                    }
                }
            }
        }

        private NtStatus ApplyByteRangeLocks(ServerOpenRecord openRecord, IReadOnlyList<Smb2LockElement> lockElements)
        {
            List<ServerByteRangeLock> pendingAdds = new List<ServerByteRangeLock>();
            List<ServerByteRangeLock> pendingRemovals = new List<ServerByteRangeLock>();

            for (int index = 0; index < lockElements.Count; index++)
            {
                Smb2LockElement element = lockElements[index];
                bool isUnlock = (element.Flags & Smb2LockFlags.Unlock) != 0;

                if (isUnlock)
                {
                    ServerByteRangeLock? existingLock = FindOwnedLock(openRecord, element.Offset, element.Length, pendingAdds, pendingRemovals);

                    if (existingLock == null)
                    {
                        return NtStatus.RangeNotLocked;
                    }

                    pendingRemovals.Add(existingLock);
                    continue;
                }

                bool requestedShared = (element.Flags & Smb2LockFlags.SharedLock) != 0;

                if (HasConflictingLock(openRecord, element.Offset, element.Length, requestedShared, pendingAdds, pendingRemovals))
                {
                    return NtStatus.LockNotGranted;
                }

                pendingAdds.Add(new ServerByteRangeLock
                {
                    OwnerVolatileFileId = openRecord.State.VolatileFileId,
                    Offset = element.Offset,
                    Length = element.Length,
                    IsShared = requestedShared
                });
            }

            for (int index = 0; index < pendingRemovals.Count; index++)
            {
                openRecord.Locks.Remove(pendingRemovals[index]);
            }

            for (int index = 0; index < pendingAdds.Count; index++)
            {
                openRecord.Locks.Add(pendingAdds[index]);
            }

            return NtStatus.Success;
        }

        private bool HasConflictingReadLock(ServerOpenRecord openRecord, ulong offset, ulong length)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (!byteRangeLock.IsShared && byteRangeLock.OwnerVolatileFileId != openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset) &&
                    !detachedLock.IsShared)
                {
                    return true;
                }
            }

            return false;
        }

        private bool HasConflictingWriteLock(ServerOpenRecord openRecord, ulong offset, ulong length)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (byteRangeLock.OwnerVolatileFileId != openRecord.State.VolatileFileId || byteRangeLock.IsShared)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset))
                {
                    return true;
                }
            }

            return false;
        }

        private ServerByteRangeLock? FindOwnedLock(
            ServerOpenRecord openRecord,
            ulong offset,
            ulong length,
            IReadOnlyList<ServerByteRangeLock> pendingAdds,
            IReadOnlyList<ServerByteRangeLock> pendingRemovals)
        {
            for (int index = pendingAdds.Count - 1; index >= 0; index--)
            {
                ServerByteRangeLock pendingLock = pendingAdds[index];

                if (pendingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId &&
                    pendingLock.Offset == offset &&
                    pendingLock.Length == length)
                {
                    return pendingLock;
                }
            }

            for (int index = 0; index < openRecord.Locks.Count; index++)
            {
                ServerByteRangeLock existingLock = openRecord.Locks[index];

                if (ContainsLockReference(pendingRemovals, existingLock))
                {
                    continue;
                }

                if (existingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId &&
                    existingLock.Offset == offset &&
                    existingLock.Length == length)
                {
                    return existingLock;
                }
            }

            return null;
        }

        private bool HasConflictingLock(
            ServerOpenRecord openRecord,
            ulong offset,
            ulong length,
            bool requestedShared,
            IReadOnlyList<ServerByteRangeLock> pendingAdds,
            IReadOnlyList<ServerByteRangeLock> pendingRemovals)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (ContainsLockReference(pendingRemovals, byteRangeLock))
                {
                    continue;
                }

                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (!requestedShared || !byteRangeLock.IsShared || byteRangeLock.OwnerVolatileFileId == openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (!RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset))
                {
                    continue;
                }

                if (!requestedShared || !detachedLock.IsShared)
                {
                    return true;
                }
            }

            for (int index = 0; index < pendingAdds.Count; index++)
            {
                ServerByteRangeLock pendingLock = pendingAdds[index];

                if (!RangesOverlap(offset, endOffset, pendingLock.Offset, pendingLock.EndOffset))
                {
                    continue;
                }

                if (!requestedShared || !pendingLock.IsShared || pendingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            return false;
        }

        private IEnumerable<ServerByteRangeLock> EnumerateLocksForPath(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (!string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        for (int index = 0; index < openRecord.Locks.Count; index++)
                        {
                            yield return openRecord.Locks[index];
                        }
                    }
                }
            }
        }

        private IEnumerable<OpenCifsServerDetachedByteRangeLock> EnumerateDetachedLocksForPath(string fullPath)
        {
            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                for (int lockIndex = 0; lockIndex < durableOpenRecord.Locks.Count; lockIndex++)
                {
                    yield return durableOpenRecord.Locks[lockIndex];
                }
            }
        }

        private static bool ContainsLockReference(IReadOnlyList<ServerByteRangeLock> locks, ServerByteRangeLock candidate)
        {
            for (int index = 0; index < locks.Count; index++)
            {
                if (ReferenceEquals(locks[index], candidate))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetRangeEnd(ulong offset, ulong length, out ulong endOffset)
        {
            try
            {
                checked
                {
                    endOffset = offset + length;
                }

                return true;
            }
            catch (OverflowException)
            {
                endOffset = 0;
                return false;
            }
        }

        private static bool RangesOverlap(ulong leftStart, ulong leftEnd, ulong rightStart, ulong rightEnd)
        {
            return leftStart < rightEnd && rightStart < leftEnd;
        }

        private NtStatus ApplyFileBasicInformation(ServerOpenRecord openRecord, FileBasicInformation information, out FileNotifyChangeFilter changeNotifyFilter)
        {
            changeNotifyFilter = FileNotifyChangeFilter.None;
            bool explicitChangeTimeApplied = false;
            bool mutatedCreationTime = false;
            bool mutatedAccessTime = false;
            bool mutatedWriteTime = false;
            bool mutatedAttributes = false;

            if (information.ChangeTime != 0)
            {
                if (IsEnableStickyFileTimeDirective(information.ChangeTime))
                {
                    openRecord.SuppressChangeTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressChangeTimeUpdates = true;

                    if (ShouldApplyExplicitFileTime(information.ChangeTime))
                    {
                        if (!TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.Change, information.ChangeTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        explicitChangeTimeApplied = true;
                    }
                }
            }

            if (ShouldApplyExplicitFileTime(information.CreationTime))
            {
                if (!TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.Creation, information.CreationTime))
                {
                    return NtStatus.InvalidParameter;
                }

                mutatedCreationTime = true;
            }

            if (information.LastAccessTime != 0)
            {
                if (IsEnableStickyFileTimeDirective(information.LastAccessTime))
                {
                    openRecord.SuppressAccessTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressAccessTimeUpdates = true;

                    if (ShouldApplyExplicitFileTime(information.LastAccessTime))
                    {
                        if (!TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.LastAccess, information.LastAccessTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        mutatedAccessTime = true;
                    }
                }
            }

            if (information.LastWriteTime != 0)
            {
                if (IsEnableStickyFileTimeDirective(information.LastWriteTime))
                {
                    openRecord.SuppressModificationTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressModificationTimeUpdates = true;

                    if (ShouldApplyExplicitFileTime(information.LastWriteTime))
                    {
                        if (!TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.LastWrite, information.LastWriteTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        mutatedWriteTime = true;
                    }
                }
            }

            if (information.FileAttributes != ProtocolFileAttributes.None)
            {
                openRecord.Backend.SetAttributes(openRecord.FullPath, MapFileAttributes(information.FileAttributes));
                mutatedAttributes = true;
            }

            if (!explicitChangeTimeApplied &&
                !openRecord.SuppressChangeTimeUpdates &&
                (mutatedCreationTime || mutatedAccessTime || mutatedWriteTime || mutatedAttributes))
            {
                SetTrackedChangeTime(openRecord.Backend, openRecord.FullPath, ToFileTimeUtc(DateTimeOffset.UtcNow));
            }

            if (mutatedCreationTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.Creation;
            }

            if (mutatedAccessTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.LastAccess;
            }

            if (mutatedWriteTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.LastWrite;
            }

            if (mutatedAttributes)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.Attributes;
            }

            return NtStatus.Success;
        }

        private void ApplyFileAllocationInformation(ServerOpenRecord openRecord, FileAllocationInformation information)
        {
            if (openRecord.Stream == null)
            {
                throw new InvalidOperationException("A file stream is required for FILE_ALLOCATION_INFORMATION.");
            }

            ulong endOfFile = unchecked((ulong)Math.Max(0L, openRecord.Stream.Length));
            SetDeclaredAllocationSize(openRecord.FullPath, information.AllocationSize, endOfFile);
            PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | NoteTimestampMutation(openRecord, updateChange: true));
        }

        private void ApplyFileEndOfFileInformation(ServerOpenRecord openRecord, FileEndOfFileInformation information)
        {
            if (openRecord.Stream == null)
            {
                throw new InvalidOperationException("A file stream is required for FILE_END_OF_FILE_INFORMATION.");
            }

            openRecord.Stream.SetLength(checked((long)information.EndOfFile));
            EnsureDeclaredAllocationSize(openRecord.FullPath, information.EndOfFile);
            PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | NoteTimestampMutation(openRecord, updateLastWrite: true, updateChange: true));
        }

        private NtStatus ApplyDeletePendingState(ServerOpenRecord openRecord, bool deletePending)
        {
            if (!deletePending)
            {
                SetDeletePendingForPath(openRecord.FullPath, deletePending: false);
                return NtStatus.Success;
            }

            SystemFileAttributes existingAttributes;

            try
            {
                existingAttributes = openRecord.Backend.GetAttributes(openRecord.FullPath);
            }
            catch (DirectoryNotFoundException)
            {
                return NtStatus.ObjectNameNotFound;
            }
            catch (FileNotFoundException)
            {
                return NtStatus.ObjectNameNotFound;
            }
            catch (UnauthorizedAccessException)
            {
                return NtStatus.AccessDenied;
            }
            catch (IOException)
            {
                return NtStatus.AccessDenied;
            }

            if ((existingAttributes & SystemFileAttributes.ReadOnly) != 0)
            {
                return NtStatus.CannotDelete;
            }

            if (openRecord.IsDirectory)
            {
                try
                {
                    if (openRecord.Backend.EnumerateFileSystemInfos(openRecord.FullPath).Count != 0)
                    {
                        return NtStatus.DirectoryNotEmpty;
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    return NtStatus.ObjectNameNotFound;
                }
                catch (UnauthorizedAccessException)
                {
                    return NtStatus.AccessDenied;
                }
                catch (IOException)
                {
                    return NtStatus.AccessDenied;
                }
            }

            SetDeletePendingForPath(openRecord.FullPath, deletePending: true);
            return NtStatus.Success;
        }

        private OpenCifsServerOperationResult<Smb2SetInfoResponse>? TryApplyRenameInformation(ServerOpenRecord openRecord, FileRenameInformationType2 information)
        {
            if (information.RootDirectory != 0)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
            }

            if (openRecord.State.IsDeletePending)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }

            string normalizedPath = NormalizeRenamePath(information.FileName);

            if (!TryResolveShareFilePath(openRecord.ShareRootPath, normalizedPath, out string? destinationFullPath, out NtStatus destinationPathStatus) || destinationFullPath == null)
            {
                return CreateOperationResult(destinationPathStatus, new Smb2SetInfoResponse());
            }

            string? destinationParent = Path.GetDirectoryName(destinationFullPath);

            if (string.IsNullOrEmpty(destinationParent) || !openRecord.Backend.DirectoryExists(destinationParent))
            {
                return CreateOperationResult(NtStatus.ObjectPathNotFound, new Smb2SetInfoResponse());
            }

            if (openRecord.Backend.DirectoryExists(destinationFullPath))
            {
                return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2SetInfoResponse());
            }

            if (openRecord.IsDirectory && HasOtherOpenRecordsWithinDirectory(openRecord.FullPath, openRecord.State.VolatileFileId))
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }

            if (string.Equals(openRecord.FullPath, destinationFullPath, StringComparison.OrdinalIgnoreCase))
            {
                UpdateOpenRecordsForRename(openRecord.FullPath, destinationFullPath, normalizedPath);
                NoteTimestampMutation(openRecord, updateChange: true);
                return null;
            }

            bool destinationExists = openRecord.Backend.FileExists(destinationFullPath);

            if (destinationExists && !information.ReplaceIfExists)
            {
                return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2SetInfoResponse());
            }

            if (destinationExists && HasOpenRecordsForPath(destinationFullPath))
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
            }

            if (destinationExists)
            {
                DeleteBackingObjectIfPresent(openRecord.Backend, destinationFullPath);
            }

            string sourceFullPath = openRecord.FullPath;

            if (openRecord.IsDirectory)
            {
                openRecord.Backend.Move(sourceFullPath, destinationFullPath, isDirectory: true);
                MoveDeclaredAllocationSizesForDirectoryRename(sourceFullPath, destinationFullPath);
                MoveTrackedFileTimestampsForDirectoryRename(sourceFullPath, destinationFullPath);
            }
            else
            {
                openRecord.Backend.Move(sourceFullPath, destinationFullPath, isDirectory: false);
                MoveDeclaredAllocationSize(sourceFullPath, destinationFullPath);
                MoveTrackedFileTimestamp(sourceFullPath, destinationFullPath);
            }

            UpdateOpenRecordsForRename(sourceFullPath, destinationFullPath, normalizedPath);
            NoteTimestampMutation(openRecord, updateChange: true);
            PublishRenameNotification(sourceFullPath, destinationFullPath, openRecord.IsDirectory);
            return null;
        }

        private bool TryValidateCreateOpenSemantics(string fullPath, uint desiredAccess, uint shareAccess, out NtStatus status)
        {
            if (HasDeletePendingConflict(fullPath))
            {
                status = NtStatus.DeletePending;
                return false;
            }

            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                if (matchingOpens[index].State.IsDeletePending)
                {
                    status = NtStatus.DeletePending;
                    return false;
                }
            }

            bool requestRead = CanReadData(desiredAccess);
            bool requestWrite = CanWrite(desiredAccess);
            bool requestDelete = CanDelete(desiredAccess);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (requestRead && (openRecord.ShareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestWrite && (openRecord.ShareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestDelete && (openRecord.ShareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanReadData && (shareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanWrite && (shareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanDelete && (shareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (durableOpenRecord.IsDeletePending)
                {
                    status = NtStatus.DeletePending;
                    return false;
                }

                if (requestRead && (durableOpenRecord.ShareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestWrite && (durableOpenRecord.ShareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestDelete && (durableOpenRecord.ShareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanReadData && (shareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanWrite && (shareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanDelete && (shareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }
            }

            status = NtStatus.Success;
            return true;
        }

        private Smb2OplockLevel DetermineGrantedCreateOplockLevel(Smb2CreateRequest request, bool isDirectoryRequest, string fullPath)
        {
            if (isDirectoryRequest)
            {
                return Smb2OplockLevel.None;
            }

            if (request.RequestedOplockLevel == Smb2OplockLevel.Batch)
            {
                return HasOpenRecordsForPath(fullPath)
                    ? Smb2OplockLevel.None
                    : Smb2OplockLevel.Batch;
            }

            if (request.RequestedOplockLevel == Smb2OplockLevel.Exclusive)
            {
                return HasOpenRecordsForPath(fullPath)
                    ? Smb2OplockLevel.None
                    : Smb2OplockLevel.Exclusive;
            }

            return Smb2OplockLevel.None;
        }

        private static Smb2LeaseState NormalizeLeaseState(Smb2LeaseState leaseState)
        {
            return leaseState & (Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching);
        }

        private Smb2LeaseState DetermineGrantedCreateLeaseState(string fullPath, OpenCifsServerLeaseRecord? existingLeaseRecord, Smb2LeaseState requestedLeaseState)
        {
            Smb2LeaseState normalizedRequestedState = NormalizeLeaseState(requestedLeaseState);

            if (existingLeaseRecord != null)
            {
                if (existingLeaseRecord.IsBreaking)
                {
                    return existingLeaseRecord.LeaseState;
                }

                if (HasConflictingOpenForLease(fullPath, existingLeaseRecord))
                {
                    return Smb2LeaseState.None;
                }

                return normalizedRequestedState == Smb2LeaseState.None
                    ? existingLeaseRecord.LeaseState
                    : normalizedRequestedState;
            }

            return HasConflictingOpenForLease(fullPath, excludedLeaseRecord: null)
                ? Smb2LeaseState.None
                : normalizedRequestedState;
        }

        private bool HasConflictingOpenForLease(string fullPath, OpenCifsServerLeaseRecord? excludedLeaseRecord)
        {
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (excludedLeaseRecord != null &&
                    ReferenceEquals(openRecord.LeaseRecord, excludedLeaseRecord))
                {
                    continue;
                }

                return true;
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private void QueueOplockBreakNotificationsForConflictingOpens(string fullPath, ServerOpenRecord excludedOpenRecord)
        {
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (ReferenceEquals(openRecord, excludedOpenRecord) ||
                    openRecord.IsDirectory ||
                    (openRecord.GrantedOplockLevel != Smb2OplockLevel.Exclusive && openRecord.GrantedOplockLevel != Smb2OplockLevel.Batch) ||
                    openRecord.IsOplockBreakInProgress)
                {
                    continue;
                }

                QueueOplockBreakNotification(openRecord, Smb2OplockLevel.None);
            }
        }

        private void QueueOplockBreakNotification(ServerOpenRecord openRecord, Smb2OplockLevel newOplockLevel)
        {
            openRecord.IsOplockBreakInProgress = true;
            openRecord.PendingOplockBreakLevel = newOplockLevel;

            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
            {
                OplockLevel = newOplockLevel,
                PersistentFileId = openRecord.State.PersistentFileId,
                VolatileFileId = openRecord.State.VolatileFileId
            };
            Smb2OplockBreakNotificationValidator.Validate(notification);
            openRecord.OwnerHost.EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
            {
                Header = openRecord.OwnerHost.CreateOplockBreakNotificationHeader(openRecord),
                Payload = notification.ToByteArray()
            });
        }

        private void QueueLeaseBreakNotificationsForConflictingOpens(string fullPath, ServerOpenRecord excludedOpenRecord)
        {
            HashSet<OpenCifsServerLeaseRecord> dispatchedLeases = new HashSet<OpenCifsServerLeaseRecord>();
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];
                OpenCifsServerLeaseRecord? leaseRecord = openRecord.LeaseRecord;

                if (leaseRecord == null ||
                    ReferenceEquals(openRecord, excludedOpenRecord) ||
                    ReferenceEquals(leaseRecord, excludedOpenRecord.LeaseRecord) ||
                    leaseRecord.LeaseState == Smb2LeaseState.None ||
                    leaseRecord.IsBreaking ||
                    !dispatchedLeases.Add(leaseRecord))
                {
                    continue;
                }

                QueueLeaseBreakNotification(openRecord, leaseRecord, Smb2LeaseState.None);
            }
        }

        private void QueueLeaseBreakNotification(ServerOpenRecord openRecord, OpenCifsServerLeaseRecord leaseRecord, Smb2LeaseState newLeaseState)
        {
            leaseRecord.IsBreaking = true;
            leaseRecord.PendingBreakLeaseState = newLeaseState;

            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
            {
                NewEpoch = 0,
                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                LeaseKey = leaseRecord.LeaseKey,
                CurrentLeaseState = leaseRecord.LeaseState,
                NewLeaseState = newLeaseState,
                BreakReason = 0,
                AccessMaskHint = 0,
                ShareMaskHint = 0
            };
            Smb2LeaseBreakNotificationValidator.Validate(notification);
            openRecord.OwnerHost.EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
            {
                Header = openRecord.OwnerHost.CreateOplockBreakNotificationHeader(openRecord),
                Payload = notification.ToByteArray()
            });
        }

        private bool HasDeletePendingConflict(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (!openRecord.State.IsDeletePending)
                        {
                            continue;
                        }

                        if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }

                        if (openRecord.IsDirectory && IsPathDescendantOf(fullPath, openRecord.FullPath))
                        {
                            return true;
                        }
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!durableOpenRecord.IsDeletePending)
                {
                    continue;
                }

                if (string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsPathDescendantOf(string fullPath, string directoryPath)
        {
            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(directoryPath))
            {
                return false;
            }

            string directoryPrefix = directoryPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? directoryPath
                : directoryPath + Path.DirectorySeparatorChar;
            return fullPath.StartsWith(directoryPrefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryCreateBackingDirectory(OpenCifsServerShareBackend backend, string fullPath, out NtStatus status)
        {
            try
            {
                backend.CreateDirectory(fullPath);
                status = NtStatus.Success;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                status = NtStatus.AccessDenied;
                return false;
            }
            catch (IOException)
            {
                status = NtStatus.AccessDenied;
                return false;
            }
        }

        private bool TryResolveShareFilePath(string shareRootPath, string relativePath, out string? fullPath, out NtStatus status, bool allowShareRoot = false)
        {
            fullPath = null;

            if (string.IsNullOrWhiteSpace(shareRootPath))
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string shareRoot;

            try
            {
                shareRoot = Path.GetFullPath(shareRootPath);
            }
            catch (Exception)
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string normalizedRelativePath = relativePath.Trim().Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar).Trim(Path.DirectorySeparatorChar);

            if (normalizedRelativePath.Length == 0)
            {
                if (!allowShareRoot)
                {
                    status = NtStatus.InvalidParameter;
                    return false;
                }

                fullPath = shareRoot;
                status = NtStatus.Success;
                return true;
            }

            string candidatePath;

            try
            {
                candidatePath = Path.GetFullPath(Path.Combine(shareRoot, normalizedRelativePath));
            }
            catch (Exception)
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string rootedPrefix = shareRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? shareRoot
                : shareRoot + Path.DirectorySeparatorChar;

            if (!candidatePath.StartsWith(rootedPrefix, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(candidatePath, shareRoot, StringComparison.OrdinalIgnoreCase))
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            fullPath = candidatePath;
            status = NtStatus.Success;
            return true;
        }

        private static bool IsShareRootOpenRequest(Smb2CreateRequest request)
        {
            return request.Name.Length == 0 &&
                (request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) == 0 &&
                (request.CreateDisposition == Smb2CreateDisposition.Open || request.CreateDisposition == Smb2CreateDisposition.OpenIf);
        }

        private void EnsureDeclaredAllocationSize(string fullPath, ulong endOfFile)
        {
            if (_DeclaredAllocationSizes.TryGetValue(fullPath, out ulong allocationSize) && allocationSize >= endOfFile)
            {
                return;
            }

            _DeclaredAllocationSizes[fullPath] = endOfFile;
        }

        private void SetDeclaredAllocationSize(string fullPath, ulong requestedAllocationSize, ulong endOfFile)
        {
            _DeclaredAllocationSizes[fullPath] = Math.Max(requestedAllocationSize, endOfFile);
        }

        private void MoveDeclaredAllocationSize(string oldFullPath, string newFullPath)
        {
            if (_DeclaredAllocationSizes.TryGetValue(oldFullPath, out ulong allocationSize))
            {
                _DeclaredAllocationSizes.Remove(oldFullPath);
                _DeclaredAllocationSizes[newFullPath] = allocationSize;
            }
        }

        private void MoveDeclaredAllocationSizesForDirectoryRename(string oldDirectoryFullPath, string newDirectoryFullPath)
        {
            string oldPrefix = oldDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? oldDirectoryFullPath
                : oldDirectoryFullPath + Path.DirectorySeparatorChar;
            string newPrefix = newDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? newDirectoryFullPath
                : newDirectoryFullPath + Path.DirectorySeparatorChar;

            List<KeyValuePair<string, ulong>> movedEntries = new List<KeyValuePair<string, ulong>>();

            foreach (KeyValuePair<string, ulong> entry in _DeclaredAllocationSizes)
            {
                if (entry.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    string suffix = entry.Key.Substring(oldPrefix.Length);
                    movedEntries.Add(new KeyValuePair<string, ulong>(newPrefix + suffix, entry.Value));
                }
            }

            for (int index = movedEntries.Count - 1; index >= 0; index--)
            {
                string suffix = movedEntries[index].Key.Substring(newPrefix.Length);
                _DeclaredAllocationSizes.Remove(oldPrefix + suffix);
            }

            for (int index = 0; index < movedEntries.Count; index++)
            {
                _DeclaredAllocationSizes[movedEntries[index].Key] = movedEntries[index].Value;
            }
        }

        private void RemoveDeclaredAllocationSize(string fullPath)
        {
            _DeclaredAllocationSizes.Remove(fullPath);
        }

        private bool TrySetTrackedFileTime(OpenCifsServerShareBackend backend, string fullPath, FileTimeField field, ulong fileTime)
        {
            if (!TryConvertFileTimeToUtcDateTime(fileTime, out DateTime utcValue))
            {
                return false;
            }

            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);

            switch (field)
            {
                case FileTimeField.Creation:
                    SetCreationTimeUtc(backend, fullPath, utcValue);
                    timestamps.CreationTime = fileTime;
                    break;
                case FileTimeField.LastAccess:
                    SetLastAccessTimeUtc(backend, fullPath, utcValue);
                    timestamps.LastAccessTime = fileTime;
                    break;
                case FileTimeField.LastWrite:
                    SetLastWriteTimeUtc(backend, fullPath, utcValue);
                    timestamps.LastWriteTime = fileTime;
                    break;
                case FileTimeField.Change:
                    timestamps.ChangeTime = fileTime;
                    break;
                default:
                    throw new InvalidOperationException("Unknown file time field.");
            }

            _TrackedFileTimestamps[fullPath] = timestamps;
            return true;
        }

        private FileNotifyChangeFilter NoteTimestampMutation(ServerOpenRecord openRecord, bool updateLastAccess = false, bool updateLastWrite = false, bool updateChange = false)
        {
            if ((updateLastAccess && openRecord.SuppressAccessTimeUpdates) ||
                !updateLastAccess)
            {
                updateLastAccess = false;
            }

            if ((updateLastWrite && openRecord.SuppressModificationTimeUpdates) ||
                !updateLastWrite)
            {
                updateLastWrite = false;
            }

            if ((updateChange && openRecord.SuppressChangeTimeUpdates) ||
                !updateChange)
            {
                updateChange = false;
            }

            if (!updateLastAccess && !updateLastWrite && !updateChange)
            {
                return FileNotifyChangeFilter.None;
            }

            ulong currentTime = ToFileTimeUtc(DateTimeOffset.UtcNow);
            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(openRecord.Backend, openRecord.FullPath);
            FileNotifyChangeFilter changeNotifyFilter = FileNotifyChangeFilter.None;

            if (updateLastAccess)
            {
                SetLastAccessTimeUtc(openRecord.Backend, openRecord.FullPath, DateTime.FromFileTimeUtc(unchecked((long)currentTime)));
                timestamps.LastAccessTime = currentTime;
                changeNotifyFilter |= FileNotifyChangeFilter.LastAccess;
            }

            if (updateLastWrite)
            {
                SetLastWriteTimeUtc(openRecord.Backend, openRecord.FullPath, DateTime.FromFileTimeUtc(unchecked((long)currentTime)));
                timestamps.LastWriteTime = currentTime;
                changeNotifyFilter |= FileNotifyChangeFilter.LastWrite;
            }

            if (updateChange)
            {
                timestamps.ChangeTime = currentTime;
            }

            _TrackedFileTimestamps[openRecord.FullPath] = timestamps;
            return changeNotifyFilter;
        }

        private void SetTrackedChangeTime(OpenCifsServerShareBackend backend, string fullPath, ulong fileTime)
        {
            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);
            timestamps.ChangeTime = fileTime;
            _TrackedFileTimestamps[fullPath] = timestamps;
        }

        private TrackedFileTimestamps GetOrCreateTrackedFileTimestamps(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (_TrackedFileTimestamps.TryGetValue(fullPath, out TrackedFileTimestamps timestamps))
            {
                return timestamps;
            }

            timestamps = ReadActualTrackedFileTimestamps(backend, fullPath);
            _TrackedFileTimestamps[fullPath] = timestamps;
            return timestamps;
        }

        private TrackedFileTimestamps ReadActualTrackedFileTimestamps(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (backend.DirectoryExists(fullPath))
            {
                DirectoryInfo directoryInfo = (DirectoryInfo)backend.GetFileSystemInfo(fullPath);
                directoryInfo.Refresh();
                ulong creationTime = unchecked((ulong)directoryInfo.CreationTimeUtc.ToFileTimeUtc());
                ulong lastAccessTime = unchecked((ulong)directoryInfo.LastAccessTimeUtc.ToFileTimeUtc());
                ulong lastWriteTime = unchecked((ulong)directoryInfo.LastWriteTimeUtc.ToFileTimeUtc());
                return new TrackedFileTimestamps
                {
                    CreationTime = creationTime,
                    LastAccessTime = lastAccessTime,
                    LastWriteTime = lastWriteTime,
                    ChangeTime = lastWriteTime
                };
            }

            FileInfo fileInfo = (FileInfo)backend.GetFileSystemInfo(fullPath);
            fileInfo.Refresh();
            ulong fileTimeCreation = fileInfo.Exists ? unchecked((ulong)fileInfo.CreationTimeUtc.ToFileTimeUtc()) : 0;
            ulong fileTimeAccess = fileInfo.Exists ? unchecked((ulong)fileInfo.LastAccessTimeUtc.ToFileTimeUtc()) : 0;
            ulong fileTimeWrite = fileInfo.Exists ? unchecked((ulong)fileInfo.LastWriteTimeUtc.ToFileTimeUtc()) : 0;
            return new TrackedFileTimestamps
            {
                CreationTime = fileTimeCreation,
                LastAccessTime = fileTimeAccess,
                LastWriteTime = fileTimeWrite,
                ChangeTime = fileTimeWrite
            };
        }

        private void MoveTrackedFileTimestamp(string oldFullPath, string newFullPath)
        {
            if (_TrackedFileTimestamps.TryGetValue(oldFullPath, out TrackedFileTimestamps timestamps))
            {
                _TrackedFileTimestamps.Remove(oldFullPath);
                _TrackedFileTimestamps[newFullPath] = timestamps;
            }
        }

        private void MoveTrackedFileTimestampsForDirectoryRename(string oldDirectoryFullPath, string newDirectoryFullPath)
        {
            MoveTrackedFileTimestamp(oldDirectoryFullPath, newDirectoryFullPath);

            string oldPrefix = oldDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? oldDirectoryFullPath
                : oldDirectoryFullPath + Path.DirectorySeparatorChar;
            string newPrefix = newDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? newDirectoryFullPath
                : newDirectoryFullPath + Path.DirectorySeparatorChar;

            List<KeyValuePair<string, TrackedFileTimestamps>> movedEntries = new List<KeyValuePair<string, TrackedFileTimestamps>>();

            foreach (KeyValuePair<string, TrackedFileTimestamps> entry in _TrackedFileTimestamps)
            {
                if (entry.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    string suffix = entry.Key.Substring(oldPrefix.Length);
                    movedEntries.Add(new KeyValuePair<string, TrackedFileTimestamps>(newPrefix + suffix, entry.Value));
                }
            }

            for (int index = movedEntries.Count - 1; index >= 0; index--)
            {
                string suffix = movedEntries[index].Key.Substring(newPrefix.Length);
                _TrackedFileTimestamps.Remove(oldPrefix + suffix);
            }

            for (int index = 0; index < movedEntries.Count; index++)
            {
                _TrackedFileTimestamps[movedEntries[index].Key] = movedEntries[index].Value;
            }
        }

        private void RemoveTrackedFileTimestamp(string fullPath)
        {
            _TrackedFileTimestamps.Remove(fullPath);
        }

        private List<ServerOpenRecord> GetOpenRecordsForPath(string fullPath)
        {
            List<ServerOpenRecord> matchingOpens = new List<ServerOpenRecord>();

            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            matchingOpens.Add(openRecord);
                        }
                    }
                }
            }

            return matchingOpens;
        }

        private bool HasOpenRecordsForPath(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private bool HasOtherOpenRecordsWithinDirectory(string directoryFullPath, ulong excludedVolatileFileId)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (openRecord.State.VolatileFileId == excludedVolatileFileId)
                        {
                            continue;
                        }

                        if (string.Equals(openRecord.FullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase) ||
                            IsPathDescendantOf(openRecord.FullPath, directoryFullPath))
                        {
                            return true;
                        }
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (string.Equals(durableOpenRecord.FullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase) ||
                    IsPathDescendantOf(durableOpenRecord.FullPath, directoryFullPath))
                {
                    return true;
                }
            }

            return false;
        }

        private void MarkDeletePendingForPath(string fullPath)
        {
            SetDeletePendingForPath(fullPath, deletePending: true);
        }

        private void SetDeletePendingForPath(string fullPath, bool deletePending)
        {
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                matchingOpens[index].State.SetDeletePending(deletePending);
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    detachedDurableOpens[index].IsDeletePending = deletePending;
                }
            }
        }

        private void UpdateOpenRecordsForRename(string oldFullPath, string newFullPath, string newRelativePath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerSessionRecord sessionRecord in host._Sessions.Values)
                {
                    foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                    {
                        if (string.Equals(openRecord.FullPath, oldFullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            openRecord.FullPath = newFullPath;
                            openRecord.State.UpdatePath(newRelativePath);
                        }
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, oldFullPath, StringComparison.OrdinalIgnoreCase))
                {
                    detachedDurableOpens[index].FullPath = newFullPath;
                    detachedDurableOpens[index].RelativePath = newRelativePath;
                }
            }
        }

        private bool DeleteBackingObjectIfPresent(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (backend.FileExists(fullPath))
            {
                try
                {
                    backend.SetAttributes(fullPath, SystemFileAttributes.Normal);
                }
                catch (FileNotFoundException)
                {
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (IOException)
                {
                }

                try
                {
                    backend.DeleteFileIfPresent(fullPath);
                }
                catch (FileNotFoundException)
                {
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }

                RemoveDeclaredAllocationSize(fullPath);
                RemoveTrackedFileTimestamp(fullPath);
                return true;
            }

            if (backend.DirectoryExists(fullPath))
            {
                try
                {
                    backend.DeleteDirectoryIfPresent(fullPath, recursive: false);
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }

                RemoveDeclaredAllocationSize(fullPath);
                RemoveTrackedFileTimestamp(fullPath);
                return true;
            }

            RemoveDeclaredAllocationSize(fullPath);
            RemoveTrackedFileTimestamp(fullPath);
            return false;
        }

        private FileMetadata BuildFileMetadata(OpenCifsServerShareBackend backend, string fullPath)
        {
            TrackedFileTimestamps trackedFileTimestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);

            if (backend.DirectoryExists(fullPath))
            {
                DirectoryInfo directoryInfo = (DirectoryInfo)backend.GetFileSystemInfo(fullPath);
                directoryInfo.Refresh();
                return new FileMetadata
                {
                    CreationTime = trackedFileTimestamps.CreationTime,
                    LastAccessTime = trackedFileTimestamps.LastAccessTime,
                    LastWriteTime = trackedFileTimestamps.LastWriteTime,
                    ChangeTime = trackedFileTimestamps.ChangeTime,
                    AllocationSize = 0,
                    EndOfFile = 0,
                    FileAttributes = MapFileAttributes(directoryInfo.Attributes)
                };
            }

            FileInfo fileInfo = (FileInfo)backend.GetFileSystemInfo(fullPath);
            fileInfo.Refresh();
            long endOfFile = fileInfo.Exists ? fileInfo.Length : 0;
            ulong effectiveEndOfFile = unchecked((ulong)Math.Max(0L, endOfFile));
            ulong allocationSize = effectiveEndOfFile;

            if (_DeclaredAllocationSizes.TryGetValue(fullPath, out ulong declaredAllocationSize))
            {
                allocationSize = Math.Max(declaredAllocationSize, effectiveEndOfFile);
            }

            return new FileMetadata
            {
                CreationTime = trackedFileTimestamps.CreationTime,
                LastAccessTime = trackedFileTimestamps.LastAccessTime,
                LastWriteTime = trackedFileTimestamps.LastWriteTime,
                ChangeTime = trackedFileTimestamps.ChangeTime,
                AllocationSize = allocationSize,
                EndOfFile = effectiveEndOfFile,
                FileAttributes = MapFileAttributes(fileInfo.Exists ? fileInfo.Attributes : SystemFileAttributes.Normal)
            };
        }

        private static SystemFileAttributes NormalizeCreateFileAttributes(ProtocolFileAttributes attributes)
        {
            const ProtocolFileAttributes directlySettableAttributes =
                ProtocolFileAttributes.ReadOnly |
                ProtocolFileAttributes.Hidden |
                ProtocolFileAttributes.System |
                ProtocolFileAttributes.Archive |
                ProtocolFileAttributes.Temporary |
                ProtocolFileAttributes.Offline |
                ProtocolFileAttributes.NotContentIndexed;

            ProtocolFileAttributes normalizedAttributes = attributes & directlySettableAttributes;
            normalizedAttributes |= ProtocolFileAttributes.Archive;
            return MapFileAttributes(normalizedAttributes);
        }

        private static ProtocolFileAttributes MapFileAttributes(SystemFileAttributes attributes)
        {
            ProtocolFileAttributes mappedAttributes = ProtocolFileAttributes.None;

            if ((attributes & SystemFileAttributes.ReadOnly) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.ReadOnly;
            }

            if ((attributes & SystemFileAttributes.Hidden) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Hidden;
            }

            if ((attributes & SystemFileAttributes.System) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.System;
            }

            if ((attributes & SystemFileAttributes.Directory) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Directory;
            }

            if ((attributes & SystemFileAttributes.Archive) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Archive;
            }

            if ((attributes & SystemFileAttributes.Temporary) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Temporary;
            }

            if ((attributes & SystemFileAttributes.SparseFile) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.SparseFile;
            }

            if ((attributes & SystemFileAttributes.ReparsePoint) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.ReparsePoint;
            }

            if ((attributes & SystemFileAttributes.Compressed) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Compressed;
            }

            if ((attributes & SystemFileAttributes.Offline) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Offline;
            }

            if ((attributes & SystemFileAttributes.NotContentIndexed) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.NotContentIndexed;
            }

            if ((attributes & SystemFileAttributes.Encrypted) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Encrypted;
            }

            return mappedAttributes == ProtocolFileAttributes.None ? ProtocolFileAttributes.Normal : mappedAttributes;
        }

        private static SystemFileAttributes MapFileAttributes(ProtocolFileAttributes attributes)
        {
            if (attributes == ProtocolFileAttributes.None || attributes == ProtocolFileAttributes.Normal)
            {
                return SystemFileAttributes.Normal;
            }

            SystemFileAttributes mappedAttributes = 0;

            if ((attributes & ProtocolFileAttributes.ReadOnly) != 0)
            {
                mappedAttributes |= SystemFileAttributes.ReadOnly;
            }

            if ((attributes & ProtocolFileAttributes.Hidden) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Hidden;
            }

            if ((attributes & ProtocolFileAttributes.System) != 0)
            {
                mappedAttributes |= SystemFileAttributes.System;
            }

            if ((attributes & ProtocolFileAttributes.Archive) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Archive;
            }

            if ((attributes & ProtocolFileAttributes.Temporary) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Temporary;
            }

            if ((attributes & ProtocolFileAttributes.SparseFile) != 0)
            {
                mappedAttributes |= SystemFileAttributes.SparseFile;
            }

            if ((attributes & ProtocolFileAttributes.ReparsePoint) != 0)
            {
                mappedAttributes |= SystemFileAttributes.ReparsePoint;
            }

            if ((attributes & ProtocolFileAttributes.Compressed) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Compressed;
            }

            if ((attributes & ProtocolFileAttributes.Offline) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Offline;
            }

            if ((attributes & ProtocolFileAttributes.NotContentIndexed) != 0)
            {
                mappedAttributes |= SystemFileAttributes.NotContentIndexed;
            }

            if ((attributes & ProtocolFileAttributes.Encrypted) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Encrypted;
            }

            return mappedAttributes == 0 ? SystemFileAttributes.Normal : mappedAttributes;
        }

        private static FileAccess DetermineFileAccess(uint desiredAccess)
        {
            bool canRead = CanReadData(desiredAccess);
            bool canWrite = CanWriteData(desiredAccess);

            if (canRead && canWrite)
            {
                return FileAccess.ReadWrite;
            }

            if (canWrite)
            {
                return FileAccess.Write;
            }

            return FileAccess.Read;
        }

        private static bool CanReadData(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData)) != 0;
        }

        private static bool CanRead(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData | FileReadAttributes)) != 0;
        }

        private static bool CanReadAttributes(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadAttributes)) != 0;
        }

        private static bool CanListDirectory(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData)) != 0;
        }

        private void PublishNameChangeNotification(string fullPath, bool isDirectory, FileNotifyAction action)
        {
            PublishChangeNotifyEvents(new ChangeNotifyEvent
            {
                FullPath = fullPath,
                Action = action,
                Filter = isDirectory ? FileNotifyChangeFilter.DirName : FileNotifyChangeFilter.FileName
            });
        }

        private void PublishModifiedNotification(string fullPath, FileNotifyChangeFilter filter)
        {
            if (filter == FileNotifyChangeFilter.None)
            {
                return;
            }

            PublishChangeNotifyEvents(new ChangeNotifyEvent
            {
                FullPath = fullPath,
                Action = FileNotifyAction.Modified,
                Filter = filter
            });
        }

        private void PublishRenameNotification(string oldFullPath, string newFullPath, bool isDirectory)
        {
            FileNotifyChangeFilter filter = isDirectory ? FileNotifyChangeFilter.DirName : FileNotifyChangeFilter.FileName;
            string? oldParent = Path.GetDirectoryName(oldFullPath);
            string? newParent = Path.GetDirectoryName(newFullPath);

            if (string.Equals(oldParent, newParent, StringComparison.OrdinalIgnoreCase))
            {
                PublishChangeNotifyEvents(
                    new ChangeNotifyEvent
                    {
                        FullPath = oldFullPath,
                        Action = FileNotifyAction.RenamedOldName,
                        Filter = filter
                    },
                    new ChangeNotifyEvent
                    {
                        FullPath = newFullPath,
                        Action = FileNotifyAction.RenamedNewName,
                        Filter = filter
                    });
                return;
            }

            PublishChangeNotifyEvents(
                new ChangeNotifyEvent
                {
                    FullPath = oldFullPath,
                    Action = FileNotifyAction.Removed,
                    Filter = filter
                },
                new ChangeNotifyEvent
                {
                    FullPath = newFullPath,
                    Action = FileNotifyAction.Added,
                    Filter = filter
                });
        }

        private void PublishChangeNotifyEvents(params ChangeNotifyEvent[] events)
        {
            if (events == null || events.Length == 0)
            {
                return;
            }

            List<PendingChangeNotifyDispatchTarget> dispatchableSubscriptions = GetDispatchableChangeNotifySubscriptions();

            for (int index = 0; index < dispatchableSubscriptions.Count; index++)
            {
                TryQueueChangeNotifyResponse(dispatchableSubscriptions[index], events);
            }
        }

        private List<PendingChangeNotifyDispatchTarget> GetDispatchableChangeNotifySubscriptions()
        {
            Dictionary<string, PendingChangeNotifyDispatchTarget> firstByOpen = new Dictionary<string, PendingChangeNotifyDispatchTarget>(StringComparer.Ordinal);

            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (PendingChangeNotifySubscription subscription in host._PendingChangeNotifySubscriptions.Values)
                {
                    string key = host._HostId.ToString("N") +
                        ":" +
                        subscription.VolatileFileId.ToString(System.Globalization.CultureInfo.InvariantCulture);

                    if (!firstByOpen.TryGetValue(key, out PendingChangeNotifyDispatchTarget? existingTarget) ||
                        subscription.SequenceId < existingTarget.Subscription.SequenceId)
                    {
                        firstByOpen[key] = new PendingChangeNotifyDispatchTarget
                        {
                            OwnerHost = host,
                            Subscription = subscription
                        };
                    }
                }
            }

            List<PendingChangeNotifyDispatchTarget> subscriptions = new List<PendingChangeNotifyDispatchTarget>(firstByOpen.Values);
            subscriptions.Sort((left, right) => left.Subscription.SequenceId.CompareTo(right.Subscription.SequenceId));
            return subscriptions;
        }

        private void TryQueueChangeNotifyResponse(PendingChangeNotifyDispatchTarget dispatchTarget, IReadOnlyList<ChangeNotifyEvent> events)
        {
            OpenCifsServerHost ownerHost = dispatchTarget.OwnerHost;
            PendingChangeNotifySubscription subscription = dispatchTarget.Subscription;

            if (!ownerHost._PendingRequests.TryGetValue(subscription.MessageId, out RequestState? requestState) || requestState == null || requestState.Header == null)
            {
                ownerHost._PendingChangeNotifySubscriptions.Remove(subscription.MessageId);
                return;
            }

            List<FileNotifyInformation> entries = new List<FileNotifyInformation>();

            for (int index = 0; index < events.Count; index++)
            {
                ChangeNotifyEvent changeEvent = events[index];

                if ((subscription.CompletionFilter & changeEvent.Filter) == 0)
                {
                    continue;
                }

                if (!TryGetChangeNotifyRelativePath(subscription, changeEvent.FullPath, out string? relativePath) || relativePath == null)
                {
                    continue;
                }

                entries.Add(new FileNotifyInformation
                {
                    Action = changeEvent.Action,
                    FileName = relativePath
                });
            }

            if (entries.Count == 0)
            {
                return;
            }

            ownerHost._PendingChangeNotifySubscriptions.Remove(subscription.MessageId);
            byte[] encodedEntries = FileNotifyInformation.EncodeEntries(entries);
            Smb2ChangeNotifyResponse response = new Smb2ChangeNotifyResponse();
            NtStatus status;

            if (subscription.OutputBufferLength == 0 || encodedEntries.Length > subscription.OutputBufferLength)
            {
                status = NtStatus.NotifyEnumDir;
                response.OutputBuffer = Array.Empty<byte>();
            }
            else
            {
                status = NtStatus.Success;
                response.OutputBuffer = encodedEntries;
            }

            Smb2ChangeNotifyResponseValidator.Validate(response);
            ownerHost.EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
            {
                Header = ownerHost.CreateResponseHeader(requestState.Header, status, sessionId: requestState.Header.SessionId, treeId: requestState.Header.TreeId),
                Payload = response.ToByteArray()
            });
        }

        private void QueueCancelledChangeNotifyResponsesForOpen(ulong volatileFileId)
        {
            List<ulong> messageIds = new List<ulong>();

            foreach (KeyValuePair<ulong, PendingChangeNotifySubscription> entry in _PendingChangeNotifySubscriptions)
            {
                if (entry.Value.VolatileFileId == volatileFileId)
                {
                    messageIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < messageIds.Count; index++)
            {
                ulong messageId = messageIds[index];
                _PendingChangeNotifySubscriptions.Remove(messageId);

                if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState) || requestState == null || requestState.Header == null)
                {
                    continue;
                }

                requestState.Cancel();
                Smb2ErrorResponse cancelledErrorResponse = new Smb2ErrorResponse();
                Smb2ErrorResponseValidator.Validate(cancelledErrorResponse);
                EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
                {
                    Header = CreateResponseHeader(requestState.Header, NtStatus.Cancelled, sessionId: requestState.Header.SessionId, treeId: requestState.Header.TreeId),
                    Payload = cancelledErrorResponse.ToByteArray()
                });
            }
        }

        private static bool TryGetChangeNotifyRelativePath(PendingChangeNotifySubscription subscription, string fullPath, out string? relativePath)
        {
            relativePath = null;

            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(subscription.DirectoryFullPath))
            {
                return false;
            }

            if (subscription.WatchTree)
            {
                string directoryPrefix = subscription.DirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                    ? subscription.DirectoryFullPath
                    : subscription.DirectoryFullPath + Path.DirectorySeparatorChar;

                if (!fullPath.StartsWith(directoryPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                relativePath = fullPath.Substring(directoryPrefix.Length);
                return relativePath.Length != 0;
            }

            string? parentDirectory = Path.GetDirectoryName(fullPath);

            if (!string.Equals(parentDirectory, subscription.DirectoryFullPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            relativePath = Path.GetFileName(fullPath);
            return !string.IsNullOrEmpty(relativePath);
        }

        private static bool CanWrite(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteData | FileAppendData | FileWriteAttributes)) != 0;
        }

        private static bool CanWriteAttributes(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteAttributes)) != 0;
        }

        private static bool CanWriteData(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteData | FileAppendData)) != 0;
        }

        private static bool CanDelete(uint desiredAccess)
        {
            return (desiredAccess & DeleteAccess) != 0;
        }

        private static bool ShouldApplyExplicitFileTime(ulong value)
        {
            return value != 0 && !IsStickyFileTimeDirective(value);
        }

        private static bool IsStickyFileTimeDirective(ulong value)
        {
            return value == StickyDisableFileTimeDirective || value == StickyEnableFileTimeDirective;
        }

        private static bool IsEnableStickyFileTimeDirective(ulong value)
        {
            return value == StickyEnableFileTimeDirective;
        }

        private static bool TryConvertFileTimeToUtcDateTime(ulong value, out DateTime utcValue)
        {
            try
            {
                long signedValue = checked((long)value);
                utcValue = DateTime.FromFileTimeUtc(signedValue);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                utcValue = default;
                return false;
            }
            catch (OverflowException)
            {
                utcValue = default;
                return false;
            }
        }

        private static void SetCreationTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetCreationTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        private static void SetLastAccessTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetLastAccessTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        private static void SetLastWriteTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetLastWriteTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        private static string NormalizeDirectorySearchPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return "*";
            }

            if (pattern.IndexOfAny(new char[] { '\\', '/' }) >= 0)
            {
                throw new ProtocolValidationException("The query-directory search pattern must not contain path separators.", nameof(pattern));
            }

            return pattern;
        }

        private List<FileSystemInfo> EnumerateMatchingDirectoryEntries(OpenCifsServerShareBackend backend, string fullPath, string pattern)
        {
            List<FileSystemInfo> matches = new List<FileSystemInfo>();
            string normalizedPattern = NormalizeDirectorySearchPattern(pattern);

            IReadOnlyList<FileSystemInfo> children = backend.EnumerateFileSystemInfos(fullPath);

            for (int index = 0; index < children.Count; index++)
            {
                FileSystemInfo child = children[index];

                if (FileSystemName.MatchesSimpleExpression(normalizedPattern, child.Name, ignoreCase: true))
                {
                    matches.Add(child);
                }
            }

            matches.Sort((left, right) => StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name));
            return matches;
        }

        private NtStatus TryBuildDirectoryEnumerationBuffer(
            OpenCifsServerShareBackend backend,
            FileInformationClass informationClass,
            IReadOnlyList<FileSystemInfo> matchingEntries,
            int startIndex,
            uint outputBufferLength,
            bool returnSingleEntry,
            out byte[] outputBuffer,
            out int returnedEntryCount)
        {
            outputBuffer = Array.Empty<byte>();
            returnedEntryCount = 0;

            switch (informationClass)
            {
                case FileInformationClass.DirectoryInformation:
                {
                    List<FileDirectoryInformationEntry> entries = new List<FileDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.FullDirectoryInformation:
                {
                    List<FileFullDirectoryInformationEntry> entries = new List<FileFullDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateFullDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileFullDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.BothDirectoryInformation:
                {
                    List<FileBothDirectoryInformationEntry> entries = new List<FileBothDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateBothDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileBothDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.IdBothDirectoryInformation:
                {
                    List<FileIdBothDirectoryInformationEntry> entries = new List<FileIdBothDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateIdBothDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileIdBothDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.IdFullDirectoryInformation:
                {
                    List<FileIdFullDirectoryInformationEntry> entries = new List<FileIdFullDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateIdFullDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileIdFullDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                default:
                    return NtStatus.InvalidInfoClass;
            }
        }

        private FileDirectoryInformationEntry CreateDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                FileName = fileSystemInfo.Name
            };
        }

        private FileFullDirectoryInformationEntry CreateFullDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileFullDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                FileName = fileSystemInfo.Name
            };
        }

        private FileBothDirectoryInformationEntry CreateBothDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileBothDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                ShortName = string.Empty,
                FileName = fileSystemInfo.Name
            };
        }

        private FileIdBothDirectoryInformationEntry CreateIdBothDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileIdBothDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                ShortName = string.Empty,
                FileId = 0,
                FileName = fileSystemInfo.Name
            };
        }

        private FileIdFullDirectoryInformationEntry CreateIdFullDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileIdFullDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                Reserved = 0,
                FileId = 0,
                FileName = fileSystemInfo.Name
            };
        }

        private static bool ValidateAuthenticateTokenTargetInfo(OpenCifsNtlmAuthenticateToken authenticateToken, string expectedServerName, string expectedUserDomain)
        {
            return ValidateAuthenticateTokenTargetInfo(authenticateToken.NtChallengeResponse, expectedServerName, expectedUserDomain);
        }

        private static bool ValidateAuthenticateTokenTargetInfo(ReadOnlySpan<byte> ntChallengeResponse, string expectedServerName, string expectedUserDomain)
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

        private bool TryGetAccount(string userName, string userDomain, out OpenCifsServerAccount? account)
        {
            return _Accounts.TryGetValue(GetAccountKey(userName, userDomain), out account);
        }

        private static string GetAccountKey(string userName, string userDomain)
        {
            return userName + "|" + userDomain;
        }

        private static string ExtractShareName(string path)
        {
            string trimmedPath = path.Trim();

            if (!trimmedPath.StartsWith("\\\\", StringComparison.Ordinal))
            {
                return trimmedPath.Trim('\\');
            }

            string[] parts = trimmedPath.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                return string.Empty;
            }

            return parts[1];
        }

        private static string FormatQueryInfoClass(Smb2QueryInfoRequest request)
        {
            if (request.InfoType == Smb2InfoType.FileSystem)
            {
                return ((FileSystemInformationClass)(byte)request.FileInfoClass).ToString();
            }

            return request.FileInfoClass.ToString();
        }

        private bool TryGetEffectiveShare(string shareName, out RegisteredShareRecord? shareRecord)
        {
            if (_RegisteredShares.TryGetValue(shareName, out shareRecord))
            {
                return true;
            }

            if (_RegisteredShares.Count == 0 && string.Equals(shareName, Options.ShareName, StringComparison.OrdinalIgnoreCase))
            {
                shareRecord = NormalizeRegisteredShare(new OpenCifsServerFileSystemShare
                {
                    ShareName = Options.ShareName,
                    RootPath = Options.SharePath,
                    CreateRootIfMissing = true
                });
                return true;
            }

            shareRecord = null;
            return false;
        }

        private static RegisteredShareRecord NormalizeRegisteredShare(OpenCifsServerShareBackend share)
        {
            share.Validate();

            string rootPath;

            try
            {
                rootPath = Path.GetFullPath(share.RootPath);
            }
            catch (Exception exception)
            {
                throw new ArgumentException("RootPath could not be resolved to a filesystem location.", nameof(share), exception);
            }

            if (share.CreateRootIfMissing)
            {
                Directory.CreateDirectory(rootPath);
            }

            return new RegisteredShareRecord
            {
                ShareName = share.ShareName,
                RootPath = rootPath,
                Backend = share.Clone()
            };
        }

        private static string NormalizeRenamePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ProtocolEncodingException("The FILE_RENAME_INFORMATION_TYPE_2 path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\').Trim('\\');

            if (normalizedPath.Length == 0)
            {
                throw new ProtocolEncodingException("The FILE_RENAME_INFORMATION_TYPE_2 path must resolve to a non-empty relative path.");
            }

            return normalizedPath;
        }

        private static ulong ToFileTimeUtc(DateTimeOffset value)
        {
            return unchecked((ulong)value.UtcDateTime.ToFileTimeUtc());
        }

        private bool TryParseInitialSessionSetupToken(ReadOnlyMemory<byte> securityBuffer, out InitialSessionSetupToken? token, out NtStatus status)
        {
            token = null;
            status = NtStatus.InvalidParameter;

            if (StartsWithNtlmSignature(securityBuffer))
            {
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
                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                selectedMechanism: out string? selectedMechanism);

            if (!selected || !string.Equals(selectedMechanism, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
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

        private static bool TryExtractStandardAuthenticateToken(ReadOnlyMemory<byte> securityBuffer, SessionSetupFlavor flavor, out byte[]? authenticateBytes, out NtStatus status)
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

        private NtlmChallengeMessage CreateStandardChallengeMessage(NtlmNegotiateMessage negotiateMessage, byte[] serverChallenge, string expectedServerName, string expectedUserDomain)
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
            timestampWriter.WriteUInt64(ToFileTimeUtc(DateTimeOffset.UtcNow));

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

        private string DetermineChallengeTargetDomain()
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
                    return Options.ServerName;
                }
            }

            return expectedDomain ?? Options.ServerName;
        }

        private static bool StartsWithNtlmSignature(ReadOnlyMemory<byte> token)
        {
            ReadOnlySpan<byte> span = token.Span;
            ReadOnlySpan<byte> signature = "NTLMSSP\0"u8;
            return span.Length >= signature.Length && span.Slice(0, signature.Length).SequenceEqual(signature);
        }

        private sealed class InitialSessionSetupToken
        {
            public SessionSetupFlavor Flavor { get; set; }

            public SpnegoNegTokenInit? SpnegoInitToken { get; set; }

            public OpenCifsNtlmNegotiateToken? LegacyNegotiateToken { get; set; }

            public NtlmNegotiateMessage? StandardNegotiateMessage { get; set; }

            public byte[]? StandardNegotiateMessageBytes { get; set; }
        }

        private enum SessionSetupFlavor
        {
            LegacyOpenCifs,
            RawNtlm,
            SpnegoNtlm
        }

        private sealed class ServerSessionRecord
        {
            public SessionState State { get; } = new SessionState();

            public Dictionary<uint, ServerTreeRecord> Trees { get; } = new Dictionary<uint, ServerTreeRecord>();

            public Dictionary<ulong, ServerOpenRecord> Opens { get; } = new Dictionary<ulong, ServerOpenRecord>();

            public string UserName { get; set; } = string.Empty;

            public string UserDomain { get; set; } = string.Empty;

            public byte[] ServerChallenge { get; set; } = Array.Empty<byte>();

            public SessionSetupFlavor SessionSetupFlavor { get; set; } = SessionSetupFlavor.LegacyOpenCifs;

            public string ExpectedServerName { get; set; } = string.Empty;

            public string ExpectedUserDomain { get; set; } = string.Empty;

            public byte[]? NegotiateMessage { get; set; }

            public byte[]? ChallengeMessage { get; set; }

            public byte[]? SessionBaseKey { get; set; }

            public byte[]? SessionKey { get; set; }
        }

        private sealed class ServerOpenRecord : IDisposable
        {
            public OpenCifsServerHost OwnerHost { get; set; } = null!;

            public ulong SessionId { get; set; }

            public uint TreeId { get; set; }

            public string ShareName { get; set; } = string.Empty;

            public string ShareRootPath { get; set; } = string.Empty;

            public OpenCifsServerShareBackend Backend { get; set; } = null!;

            public string FullPath { get; set; } = string.Empty;

            public uint DesiredAccess { get; set; }

            public uint ShareAccess { get; set; }

            public bool CanRead { get; set; }

            public bool CanWrite { get; set; }

            public bool CanReadData { get; set; }

            public bool CanWriteData { get; set; }

            public bool CanDelete { get; set; }

            public bool IsDirectory { get; set; }

            public Smb2OplockLevel GrantedOplockLevel { get; set; } = Smb2OplockLevel.None;

            public Smb2OplockLevel PendingOplockBreakLevel { get; set; } = Smb2OplockLevel.None;

            public bool IsOplockBreakInProgress { get; set; }

            public OpenCifsServerLeaseRecord? LeaseRecord { get; set; }

            public string? DirectoryEnumerationPattern { get; set; }

            public int DirectoryEnumerationIndex { get; set; }

            public List<ServerByteRangeLock> Locks { get; } = new List<ServerByteRangeLock>();

            public FileStream? Stream { get; set; }

            public OpenState State { get; set; } = null!;

            public bool SuppressAccessTimeUpdates { get; set; }

            public bool SuppressModificationTimeUpdates { get; set; }

            public bool SuppressChangeTimeUpdates { get; set; }

            public void Dispose()
            {
                Stream?.Dispose();
                State.Dispose();
            }
        }

        private sealed class RegisteredShareRecord
        {
            public string ShareName { get; set; } = string.Empty;

            public string RootPath { get; set; } = string.Empty;

            public OpenCifsServerShareBackend Backend { get; set; } = null!;
        }

        private sealed class ServerTreeRecord
        {
            public TreeConnectState State { get; } = new TreeConnectState();

            public string ShareName { get; set; } = string.Empty;

            public string ShareRootPath { get; set; } = string.Empty;

            public OpenCifsServerShareBackend Backend { get; set; } = null!;
        }

        private sealed class ServerByteRangeLock
        {
            public ulong OwnerVolatileFileId { get; set; }

            public ulong Offset { get; set; }

            public ulong Length { get; set; }

            public bool IsShared { get; set; }

            public ulong EndOffset
            {
                get
                {
                    return Offset + Length;
                }
            }
        }

        private sealed class PendingChangeNotifySubscription
        {
            public ulong SequenceId { get; set; }

            public ulong MessageId { get; set; }

            public ulong SessionId { get; set; }

            public uint TreeId { get; set; }

            public ulong PersistentFileId { get; set; }

            public ulong VolatileFileId { get; set; }

            public string DirectoryFullPath { get; set; } = string.Empty;

            public bool WatchTree { get; set; }

            public FileNotifyChangeFilter CompletionFilter { get; set; } = FileNotifyChangeFilter.None;

            public uint OutputBufferLength { get; set; }
        }

        private sealed class PendingChangeNotifyDispatchTarget
        {
            public OpenCifsServerHost OwnerHost { get; set; } = null!;

            public PendingChangeNotifySubscription Subscription { get; set; } = null!;
        }

        private struct ChangeNotifyEvent
        {
            public string FullPath;

            public FileNotifyAction Action;

            public FileNotifyChangeFilter Filter;
        }

        private sealed class RelatedCompoundContext
        {
            public ulong SessionId { get; private set; }

            public uint TreeId { get; private set; }

            public ulong PersistentFileId { get; private set; }

            public ulong VolatileFileId { get; private set; }

            public bool HasSessionId { get; private set; }

            public bool HasTreeId { get; private set; }

            public bool HasFileId { get; private set; }

            public bool PreviousCouldGenerateFileId { get; private set; }

            public NtStatus PreviousStatus { get; private set; } = NtStatus.Success;

            public void Update(NtStatus status, ulong sessionId, bool hasSessionId, uint treeId, bool hasTreeId, ulong persistentFileId, ulong volatileFileId, bool hasFileId, bool previousCouldGenerateFileId)
            {
                PreviousStatus = status;
                SessionId = sessionId;
                HasSessionId = hasSessionId;
                TreeId = treeId;
                HasTreeId = hasTreeId;
                PersistentFileId = persistentFileId;
                VolatileFileId = volatileFileId;
                HasFileId = hasFileId;
                PreviousCouldGenerateFileId = previousCouldGenerateFileId;
            }
        }

        private struct FileMetadata
        {
            public ulong CreationTime;

            public ulong LastAccessTime;

            public ulong LastWriteTime;

            public ulong ChangeTime;

            public ulong AllocationSize;

            public ulong EndOfFile;

            public ProtocolFileAttributes FileAttributes;
        }

        private struct VolumeCapacitySnapshot
        {
            public ulong TotalAllocationUnits;

            public ulong AvailableAllocationUnits;
        }

        private struct TrackedFileTimestamps
        {
            public ulong CreationTime;

            public ulong LastAccessTime;

            public ulong LastWriteTime;

            public ulong ChangeTime;
        }

        private enum FileTimeField
        {
            Creation,
            LastAccess,
            LastWrite,
            Change
        }
    }
}

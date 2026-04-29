namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Transport;

    /// <summary>
    /// Managed direct-TCP client connection surface for SMB 2.0.2 session, tree, open, query, set, enumerate, and close flows.
    /// </summary>
    public sealed class OpenCifsClientConnection : IDisposable, IAsyncDisposable
    {
        private const uint DefaultDesiredAccess = 0xC0000000U;
        private const uint DefaultShareAccess = 0x00000007U;
        private const uint DefaultQueryBufferLength = 4096;
        private const uint DefaultChangeNotifyBufferLength = 4096;

        /// <summary>
        /// Initialize a managed direct-TCP client connection.
        /// </summary>
        /// <param name="options">Client options.</param>
        public OpenCifsClientConnection(OpenCifsClientOptions options)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            Options.Validate();
            _Session = new OpenCifsClientSession(Options);
        }

        /// <summary>
        /// Client options.
        /// </summary>
        public OpenCifsClientOptions Options { get; }

        /// <summary>
        /// Current low-level client session for the active or next connection lifecycle.
        /// </summary>
        public OpenCifsClientSession Session
        {
            get
            {
                return _Session;
            }
        }

        /// <summary>
        /// Whether a direct-TCP transport connection is currently active.
        /// </summary>
        public bool IsConnected
        {
            get
            {
                return _Connection != null;
            }
        }

        /// <summary>
        /// Whether the active client session is authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return _Session.IsAuthenticated;
            }
        }

        /// <summary>
        /// Connect and negotiate against the configured direct-TCP endpoint.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_Connection != null)
            {
                throw new InvalidOperationException("The client connection is already connected.");
            }

            ResetSession();

            using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(Options.ConnectTimeoutMs);
            using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
            CancellationToken linkedToken = linkedTokenSource.Token;

            try
            {
                _TcpClient = new TcpClient();
                await _TcpClient.ConnectAsync(Options.ServerName, Options.ServerPort, linkedToken).ConfigureAwait(false);
                NetworkStream networkStream = _TcpClient.GetStream();
                _Connection = FramedPipeConnection.Create(networkStream, new DirectTcpFrameProtocol());
                _Connection.Start();
                await NegotiateAsync(linkedToken).ConfigureAwait(false);
            }
            catch
            {
                await ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
                throw;
            }
        }

        /// <summary>
        /// Connect, negotiate, and authenticate against the configured direct-TCP endpoint.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task ConnectAndAuthenticateAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            await ConnectAsync(cancellationToken).ConfigureAwait(false);
            await AuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Authenticate the active direct-TCP session.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task AuthenticateAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            EnsureNegotiatedConnection();

            if (_Session.IsAuthenticated)
            {
                throw new InvalidOperationException("The client connection is already authenticated.");
            }

            try
            {
                Smb2Header challengeHeader = _Session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                Smb2SessionSetupRequest initialRequest = _Session.CreateSessionSetupRequest(credential);
                (Smb2Header challengeResponseHeader, byte[] challengeResponsePayload) = await SendSingleRequestAsync(
                    challengeHeader,
                    initialRequest.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);

                if (challengeResponseHeader.Status != NtStatus.MoreProcessingRequired)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(
                        Smb2Command.SessionSetup,
                        challengeResponseHeader.Status,
                        challengeResponsePayload);
                }

                Smb2SessionSetupResponse challengeResponse = Smb2SessionSetupResponse.ReadFrom(challengeResponsePayload);
                Smb2SessionSetupRequest authenticateRequest = _Session.CreateSessionAuthenticateRequest(
                    credential,
                    challengeResponseHeader.SessionId,
                    challengeResponseHeader.Status,
                    challengeResponse);
                Smb2Header authenticateHeader = _Session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResponseHeader.SessionId);
                (Smb2Header authenticateResponseHeader, byte[] authenticateResponsePayload) = await SendSingleRequestAsync(
                    authenticateHeader,
                    authenticateRequest.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);

                if (authenticateResponseHeader.Status != NtStatus.Success)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(
                        Smb2Command.SessionSetup,
                        authenticateResponseHeader.Status,
                        authenticateResponsePayload);
                }

                _Session.ApplySessionSetupResult(
                    authenticateResponseHeader.SessionId,
                    authenticateResponseHeader.Status,
                    Smb2SessionSetupResponse.ReadFrom(authenticateResponsePayload));
            }
            catch
            {
                await ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
                throw;
            }
        }

        /// <summary>
        /// Send an authenticated SMB2 echo request.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task EchoAsync(CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Echo, sessionId: _Session.SessionId!.Value);
            Smb2EchoRequest request = _Session.CreateEchoRequest();
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyEchoResult(
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2EchoResponse.ReadFrom));
        }

        /// <summary>
        /// Expand the authenticated SMB2 credit window as far as the current server permits.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Available credits after the expansion attempt.</returns>
        public async Task<int> RequestMaximumCreditsAsync(CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();
            int previousCredits = -1;

            while (_Session.AvailableCredits > previousCredits)
            {
                previousCredits = _Session.AvailableCredits;
                await RequestCreditWindowGrowthAsync(UInt16.MaxValue, cancellationToken).ConfigureAwait(false);
            }

            return _Session.AvailableCredits;
        }

        /// <summary>
        /// Connect a tree for the specified share name.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Tracked tree handle.</returns>
        public async Task<OpenCifsClientTreeHandle> TreeConnectAsync(string shareName, CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            string normalizedShareName = shareName.Trim('\\');
            Smb2TreeConnectRequest request = _Session.CreateTreeConnectRequest(normalizedShareName);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyTreeConnectResult(
                normalizedShareName,
                responseHeader.TreeId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2TreeConnectResponse.ReadFrom));
            OpenCifsClientTreeHandle handle = new OpenCifsClientTreeHandle(_ConnectionId, _SessionGeneration, normalizedShareName, responseHeader.TreeId);
            _ActiveTreesById[handle.TreeId] = handle;
            return handle;
        }

        /// <summary>
        /// Disconnect a previously connected tree handle.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task TreeDisconnectAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);
            Smb2TreeDisconnectRequest request = _Session.CreateTreeDisconnectRequest(treeHandle.TreeId);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.TreeDisconnect, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyTreeDisconnectResult(
                treeHandle.TreeId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2TreeDisconnectResponse.ReadFrom));
            MarkTreeDisconnected(treeHandle);
        }

        /// <summary>
        /// Create or open a path under a connected tree.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="desiredAccess">Desired access mask.</param>
        /// <param name="fileAttributes">Create-time file attributes.</param>
        /// <param name="shareAccess">Share-access mask.</param>
        /// <param name="createDisposition">Create disposition.</param>
        /// <param name="createOptions">Create options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="requestedOplockLevel">Requested oplock level.</param>
        /// <param name="requestDurableHandle">Whether to request a bounded SMB 2.0.2 durable open.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key. When omitted, a random key is generated.</param>
        /// <returns>Tracked open handle.</returns>
        public async Task<OpenCifsClientOpenHandle> OpenAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess = DefaultDesiredAccess,
            FileAttributes fileAttributes = FileAttributes.Normal,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.Open,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default,
            Smb2OplockLevel requestedOplockLevel = Smb2OplockLevel.None,
            bool requestDurableHandle = false,
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.None,
            byte[]? leaseKey = null)
        {
            ValidateTreeHandle(treeHandle);
            Smb2OplockLevel effectiveOplockLevel = requestDurableHandle && requestedOplockLevel == Smb2OplockLevel.None
                ? Smb2OplockLevel.Batch
                : requestedOplockLevel;
            Smb2CreateRequest request = _Session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                effectiveOplockLevel,
                requestDurableHandle,
                requestedLeaseState,
                leaseKey);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2CreateResponse.ReadFrom);
            return CreateOpenHandle(
                treeHandle,
                path,
                responseHeader,
                createResponse,
                (createOptions & Smb2CreateOptions.DirectoryFile) != 0,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                effectiveOplockLevel);
        }

        /// <summary>
        /// Open an existing path, retrying with directory semantics when the server reports a directory target.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="desiredAccess">Desired access mask.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="requestedOplockLevel">Requested oplock level.</param>
        /// <param name="requestDurableHandle">Whether to request a bounded SMB 2.0.2 durable open.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key. When omitted, a random key is generated.</param>
        /// <returns>Tracked open handle.</returns>
        public async Task<OpenCifsClientOpenHandle> OpenExistingPathAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess = DefaultDesiredAccess,
            CancellationToken cancellationToken = default,
            Smb2OplockLevel requestedOplockLevel = Smb2OplockLevel.None,
            bool requestDurableHandle = false,
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.None,
            byte[]? leaseKey = null)
        {
            ValidateTreeHandle(treeHandle);
            Smb2OplockLevel effectiveOplockLevel = requestDurableHandle && requestedOplockLevel == Smb2OplockLevel.None
                ? Smb2OplockLevel.Batch
                : requestedOplockLevel;
            (Smb2Header responseHeader, byte[] responsePayload) = await SendOpenExistingCreateAsync(
                treeHandle,
                path,
                desiredAccess,
                    Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken,
                    effectiveOplockLevel,
                    requestDurableHandle,
                    requestedLeaseState,
                    leaseKey).ConfigureAwait(false);
            bool isDirectory = false;
            Smb2CreateOptions appliedCreateOptions = Smb2CreateOptions.NonDirectoryFile;

            if (responseHeader.Status == NtStatus.FileIsADirectory)
            {
                (responseHeader, responsePayload) = await SendOpenExistingCreateAsync(
                    treeHandle,
                    path,
                    desiredAccess,
                    Smb2CreateOptions.DirectoryFile,
                    cancellationToken,
                    effectiveOplockLevel,
                    requestDurableHandle,
                    requestedLeaseState,
                    leaseKey).ConfigureAwait(false);
                isDirectory = true;
                appliedCreateOptions = Smb2CreateOptions.DirectoryFile;
            }

            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2CreateResponse.ReadFrom);
            return CreateOpenHandle(
                treeHandle,
                path,
                responseHeader,
                createResponse,
                isDirectory,
                desiredAccess,
                FileAttributes.Normal,
                DefaultShareAccess,
                Smb2CreateDisposition.Open,
                appliedCreateOptions,
                effectiveOplockLevel);
        }

        /// <summary>
        /// Re-establish a previously granted durable open on the current authenticated session and tree.
        /// </summary>
        /// <param name="treeHandle">Connected tree handle on the new session.</param>
        /// <param name="durableOpenHandle">Handle from the original connection lifecycle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Reconnected open handle.</returns>
        public async Task<OpenCifsClientOpenHandle> ReconnectDurableOpenAsync(
            OpenCifsClientTreeHandle treeHandle,
            OpenCifsClientOpenHandle durableOpenHandle,
            CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);

            if (durableOpenHandle == null)
            {
                throw new ArgumentNullException(nameof(durableOpenHandle), "DurableOpenHandle cannot be null.");
            }

            if (!durableOpenHandle.CanReconnectDurably)
            {
                throw new InvalidOperationException("The specified open handle is not currently usable as a durable reconnect token.");
            }

            if (durableOpenHandle.IsDirectory)
            {
                throw new InvalidOperationException("Durable reconnect is bounded to file opens in the current SMB 2.0.2 slice.");
            }

            Smb2CreateRequest request = _Session.CreateDurableReconnectCreateRequest(
                treeHandle.TreeId,
                durableOpenHandle.Path,
                durableOpenHandle.PersistentFileId,
                durableOpenHandle.VolatileFileId,
                durableOpenHandle.DesiredAccess,
                durableOpenHandle.FileAttributes,
                durableOpenHandle.ShareAccess,
                durableOpenHandle.CreateDisposition,
                durableOpenHandle.CreateOptions,
                durableOpenHandle.RequestedOplockLevel,
                durableOpenHandle.LeaseState,
                durableOpenHandle.LeaseKey.Length == 16 ? durableOpenHandle.LeaseKey : null);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2CreateResponse.ReadFrom);
            durableOpenHandle.MarkClosed();
            durableOpenHandle.InvalidateDurableReconnect();
            return CreateOpenHandle(
                treeHandle,
                durableOpenHandle.Path,
                responseHeader,
                createResponse,
                isDirectory: false,
                durableOpenHandle.DesiredAccess,
                durableOpenHandle.FileAttributes,
                durableOpenHandle.ShareAccess,
                durableOpenHandle.CreateDisposition,
                durableOpenHandle.CreateOptions,
                durableOpenHandle.RequestedOplockLevel);
        }

        /// <summary>
        /// Wait for the next unsolicited SMB2 oplock-break notification on the active connection and send any required acknowledgment.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Applied oplock-break notification.</returns>
        public async Task<OpenCifsClientOplockBreakNotification> WaitForOplockBreakAsync(CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();

            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            byte[] responseBytes = await _Connection.ReadAsync(cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            _Session.ValidateOplockBreakNotificationPacket(responsePacket, responseBytes);
            Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];
            Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(GetResponsePayloadBytes(responseEntry));
            (OpenState openState, Smb2OplockLevel previousOplockLevel, Smb2OplockLevel newOplockLevel, bool requiresAcknowledgment) = _Session.ApplyOplockBreakNotification(
                responseEntry.Header.TreeId,
                notification);
            OpenCifsClientOpenHandle openHandle = GetTrackedOpenHandle(openState.PersistentFileId, openState.VolatileFileId);
            openHandle.SetOplockLevel(newOplockLevel);
            bool wasAcknowledged = false;

            if (requiresAcknowledgment)
            {
                Smb2OplockBreakAcknowledgment acknowledgment = _Session.CreateOplockBreakAcknowledgmentRequest(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    newOplockLevel);
                Smb2Header acknowledgmentHeader = _Session.CreateRequestHeader(Smb2Command.OplockBreak, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
                (Smb2Header ackResponseHeader, byte[] ackResponsePayload) = await SendSingleRequestAsync(
                    acknowledgmentHeader,
                    acknowledgment.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);
                _Session.ApplyOplockBreakAcknowledgmentResult(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    ackResponseHeader.Status,
                    Smb2OplockBreakResponse.ReadFrom(ackResponsePayload));
                openHandle.SetOplockLevel(newOplockLevel);
                wasAcknowledged = true;
            }

            return new OpenCifsClientOplockBreakNotification
            {
                ShareName = openHandle.ShareName,
                Path = openHandle.Path,
                PersistentFileId = openHandle.PersistentFileId,
                VolatileFileId = openHandle.VolatileFileId,
                PreviousOplockLevel = previousOplockLevel,
                NewOplockLevel = newOplockLevel,
                WasAcknowledged = wasAcknowledged
            };
        }

        /// <summary>
        /// Wait for the next unsolicited SMB2 lease-break notification on the active connection and send any required acknowledgment.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Applied lease-break notification.</returns>
        public async Task<OpenCifsClientLeaseBreakNotification> WaitForLeaseBreakAsync(CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();

            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            byte[] responseBytes = await _Connection.ReadAsync(cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            _Session.ValidateLeaseBreakNotificationPacket(responsePacket, responseBytes);
            Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];
            Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(GetResponsePayloadBytes(responseEntry));
            (OpenState openState, Smb2LeaseState previousLeaseState, Smb2LeaseState newLeaseState, bool requiresAcknowledgment) = _Session.ApplyLeaseBreakNotification(
                responseEntry.Header.TreeId,
                notification);
            OpenCifsClientOpenHandle openHandle = GetTrackedOpenHandle(openState.PersistentFileId, openState.VolatileFileId);
            openHandle.SetLeaseState(newLeaseState);
            bool wasAcknowledged = false;

            if (requiresAcknowledgment)
            {
                Smb2LeaseBreakAcknowledgment acknowledgment = _Session.CreateLeaseBreakAcknowledgmentRequest(
                    openState.PersistentFileId,
                    openState.VolatileFileId);
                Smb2Header acknowledgmentHeader = _Session.CreateRequestHeader(Smb2Command.OplockBreak, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
                (Smb2Header ackResponseHeader, byte[] ackResponsePayload) = await SendSingleRequestAsync(
                    acknowledgmentHeader,
                    acknowledgment.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);
                _Session.ApplyLeaseBreakAcknowledgmentResult(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    ackResponseHeader.Status,
                    Smb2LeaseBreakResponse.ReadFrom(ackResponsePayload));
                openHandle.SetLeaseState(newLeaseState);
                wasAcknowledged = true;
            }

            return new OpenCifsClientLeaseBreakNotification
            {
                ShareName = openHandle.ShareName,
                Path = openHandle.Path,
                PersistentFileId = openHandle.PersistentFileId,
                VolatileFileId = openHandle.VolatileFileId,
                PreviousLeaseState = previousLeaseState,
                NewLeaseState = newLeaseState,
                WasAcknowledged = wasAcknowledged
            };
        }

        /// <summary>
        /// Read a byte range from an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="length">Requested read length.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="minimumCount">Minimum read length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Read bytes.</returns>
        public async Task<byte[]> ReadAsync(
            OpenCifsClientOpenHandle openHandle,
            uint length,
            ulong offset,
            uint minimumCount = 0,
            CancellationToken cancellationToken = default)
        {
            ValidateFileOpenHandle(openHandle, "SMB2 read");
            ushort requiredCredits = _Session.GetRequiredReadWriteCredits(length);
            ushort creditCharge = _Session.GetReadWriteCreditCharge(length);
            await EnsureCreditsAsync(requiredCredits, cancellationToken).ConfigureAwait(false);
            Smb2ReadRequest request = _Session.CreateReadRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, length, offset, minimumCount);
            Smb2Header requestHeader = _Session.CreateRequestHeader(
                Smb2Command.Read,
                openHandle.TreeId,
                creditRequest: requiredCredits,
                sessionId: _Session.SessionId!.Value,
                creditCharge: creditCharge);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            return _Session.ApplyReadResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2ReadResponse.ReadFrom));
        }

        /// <summary>
        /// Write a byte buffer to an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Acknowledged write length.</returns>
        public async Task<uint> WriteAsync(OpenCifsClientOpenHandle openHandle, byte[] data, ulong offset, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            ValidateFileOpenHandle(openHandle, "SMB2 write");
            ushort requiredCredits = _Session.GetRequiredReadWriteCredits(checked((uint)data.Length));
            ushort creditCharge = _Session.GetReadWriteCreditCharge(checked((uint)data.Length));
            await EnsureCreditsAsync(requiredCredits, cancellationToken).ConfigureAwait(false);
            Smb2WriteRequest request = _Session.CreateWriteRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, data, offset);
            Smb2Header requestHeader = _Session.CreateRequestHeader(
                Smb2Command.Write,
                openHandle.TreeId,
                creditRequest: requiredCredits,
                sessionId: _Session.SessionId!.Value,
                creditCharge: creditCharge);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            return _Session.ApplyWriteResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2WriteResponse.ReadFrom));
        }

        /// <summary>
        /// Flush an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task FlushAsync(OpenCifsClientOpenHandle openHandle, CancellationToken cancellationToken = default)
        {
            ValidateFileOpenHandle(openHandle, "SMB2 flush");
            Smb2FlushRequest request = _Session.CreateFlushRequest(openHandle.PersistentFileId, openHandle.VolatileFileId);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Flush, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyFlushResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2FlushResponse.ReadFrom));
        }

        /// <summary>
        /// Apply one or more byte-range lock or unlock elements to an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="locks">Requested lock elements.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task LockAsync(OpenCifsClientOpenHandle openHandle, Smb2LockElement[] locks, CancellationToken cancellationToken = default)
        {
            ValidateFileOpenHandle(openHandle, "SMB2 lock");

            if (locks == null)
            {
                throw new ArgumentNullException(nameof(locks), "Locks cannot be null.");
            }

            Smb2LockRequest request = _Session.CreateLockRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, locks);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Lock, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyLockResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2LockResponse.ReadFrom));
        }

        /// <summary>
        /// Query file information for an existing open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="informationClass">Requested file-information class.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded output buffer.</returns>
        public async Task<byte[]> QueryInfoAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            CancellationToken cancellationToken = default)
        {
            ValidateOpenHandle(openHandle);
            Smb2QueryInfoRequest request = _Session.CreateQueryInfoRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                informationClass,
                outputBufferLength);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.QueryInfo, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            return _Session.ApplyQueryInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2QueryInfoResponse.ReadFrom));
        }

        /// <summary>
        /// Enumerate an existing directory open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="informationClass">Requested directory-information class.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="flags">Query-directory flags.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded output buffer.</returns>
        public async Task<byte[]> QueryDirectoryAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            string? fileNamePattern = null,
            Smb2QueryDirectoryFlags flags = Smb2QueryDirectoryFlags.RestartScans,
            CancellationToken cancellationToken = default)
        {
            ValidateDirectoryOpenHandle(openHandle, "SMB2 query directory");
            Smb2QueryDirectoryRequest request = _Session.CreateQueryDirectoryRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                informationClass,
                outputBufferLength,
                string.IsNullOrWhiteSpace(fileNamePattern) ? "*" : fileNamePattern,
                flags);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.QueryDirectory, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            return _Session.ApplyQueryDirectoryResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2QueryDirectoryResponse.ReadFrom));
        }

        /// <summary>
        /// Wait for a bounded SMB2 CHANGE_NOTIFY completion on an existing directory open.
        /// </summary>
        /// <param name="openHandle">Tracked directory open handle.</param>
        /// <param name="completionFilter">Requested completion filter.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the open directory.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded notify entries.</returns>
        public async Task<FileNotifyInformation[]> ChangeNotifyAsync(
            OpenCifsClientOpenHandle openHandle,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            uint outputBufferLength = DefaultChangeNotifyBufferLength,
            CancellationToken cancellationToken = default)
        {
            ValidateDirectoryOpenHandle(openHandle, "SMB2 change notify");
            Smb2ChangeNotifyRequest request = _Session.CreateChangeNotifyRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                completionFilter,
                watchTree,
                outputBufferLength);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.ChangeNotify, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload, bool cancelledByClient) = await SendChangeNotifyRequestAsync(
                requestHeader,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);

            if (cancelledByClient)
            {
                throw new OperationCanceledException("The SMB2 CHANGE_NOTIFY request was cancelled.", cancellationToken);
            }

            return _Session.ApplyChangeNotifyResult(
                request,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2ChangeNotifyResponse.ReadFrom));
        }

        /// <summary>
        /// Apply a FILE_BASIC_INFORMATION mutation to an existing open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="information">Basic-information payload.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetBasicInfoAsync(OpenCifsClientOpenHandle openHandle, FileBasicInformation information, CancellationToken cancellationToken = default)
        {
            if (information == null)
            {
                throw new ArgumentNullException(nameof(information), "Information cannot be null.");
            }

            ValidateOpenHandle(openHandle);
            Smb2SetInfoRequest request = _Session.CreateSetBasicInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, information);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Apply a FILE_END_OF_FILE_INFORMATION mutation to an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetEndOfFileAsync(OpenCifsClientOpenHandle openHandle, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            ValidateFileOpenHandle(openHandle, "SMB2 set end-of-file");
            Smb2SetInfoRequest request = _Session.CreateSetEndOfFileInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, endOfFile);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Apply a FILE_ALLOCATION_INFORMATION mutation to an existing file open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="allocationSize">Requested allocation size.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetAllocationSizeAsync(OpenCifsClientOpenHandle openHandle, ulong allocationSize, CancellationToken cancellationToken = default)
        {
            ValidateFileOpenHandle(openHandle, "SMB2 set allocation size");
            Smb2SetInfoRequest request = _Session.CreateSetAllocationInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, allocationSize);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Apply FILE_DISPOSITION_INFORMATION to an existing file or directory open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="deletePending">Delete-pending state.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetDeletePendingAsync(OpenCifsClientOpenHandle openHandle, bool deletePending = true, CancellationToken cancellationToken = default)
        {
            ValidateOpenHandle(openHandle);
            Smb2SetInfoRequest request = _Session.CreateSetDispositionInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, deletePending);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.SetInfo, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplySetDispositionInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2SetInfoResponse.ReadFrom),
                deletePending);
            openHandle.SetDeletePending(deletePending);
        }

        /// <summary>
        /// Apply FILE_RENAME_INFORMATION to an existing file or directory open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="path">New relative path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetRenameAsync(
            OpenCifsClientOpenHandle openHandle,
            string path,
            bool replaceIfExists = false,
            CancellationToken cancellationToken = default)
        {
            ValidateOpenHandle(openHandle);
            Smb2SetInfoRequest request = _Session.CreateSetRenameInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, path, replaceIfExists);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.SetInfo, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplySetRenameInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2SetInfoResponse.ReadFrom),
                path);
            openHandle.UpdatePath(NormalizeRelativePath(path));
        }

        /// <summary>
        /// Close an existing file or directory open.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="postQueryAttributes">Whether to request post-close attributes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Close response.</returns>
        public async Task<Smb2CloseResponse> CloseAsync(
            OpenCifsClientOpenHandle openHandle,
            bool postQueryAttributes = false,
            CancellationToken cancellationToken = default)
        {
            ValidateOpenHandle(openHandle);
            Smb2CloseRequest request = _Session.CreateCloseRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, postQueryAttributes);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Close, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2CloseResponse response = ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2CloseResponse.ReadFrom);
            _Session.ApplyCloseResult(openHandle.PersistentFileId, openHandle.VolatileFileId, responseHeader.Status, response);
            RemoveOpenHandle(openHandle);
            return response;
        }

        /// <summary>
        /// Disconnect all active trees, log off the session, and close the underlying transport.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            await DisconnectCoreAsync(cancellationToken).ConfigureAwait(false);
        }

        internal async Task SimulateTransportDisconnectAsync()
        {
            ThrowIfDisposed();

            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            await ResetTransportAsync().ConfigureAwait(false);
            ResetSession(invalidateDurableReconnect: false);

            // This helper exists for the shared direct-TCP tests. Give the server a brief
            // window to observe the abrupt socket teardown and detach any durable state
            // before the test issues competing or reconnecting operations.
            await Task.Delay(200).ConfigureAwait(false);
        }

        /// <summary>
        /// Dispose the client connection and release any active transport.
        /// </summary>
        public void Dispose()
        {
            if (_Disposed || _AsyncDisposed)
            {
                return;
            }

            DisposeAsyncCore().AsTask().GetAwaiter().GetResult();
            _Disposed = true;
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose the client connection and release any active transport asynchronously.
        /// </summary>
        /// <returns>Completion task.</returns>
        public async ValueTask DisposeAsync()
        {
            if (_AsyncDisposed || _Disposed)
            {
                return;
            }

            await DisposeAsyncCore().ConfigureAwait(false);
            _AsyncDisposed = true;
            GC.SuppressFinalize(this);
        }

        private async ValueTask DisposeAsyncCore()
        {
            try
            {
                await DisconnectCoreAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                await ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
            }
        }

        private async Task DisconnectCoreAsync(CancellationToken cancellationToken)
        {
            if (_Connection == null)
            {
                ResetSession();
                return;
            }

            try
            {
                List<OpenCifsClientTreeHandle> connectedTrees = new List<OpenCifsClientTreeHandle>(_ActiveTreesById.Values);

                for (int index = 0; index < connectedTrees.Count; index++)
                {
                    OpenCifsClientTreeHandle treeHandle = connectedTrees[index];

                    if (treeHandle.IsDisconnected)
                    {
                        continue;
                    }

                    Smb2TreeDisconnectRequest treeDisconnectRequest = _Session.CreateTreeDisconnectRequest(treeHandle.TreeId);
                    Smb2Header treeDisconnectHeader = _Session.CreateRequestHeader(Smb2Command.TreeDisconnect, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
                    (Smb2Header treeDisconnectResponseHeader, byte[] treeDisconnectResponsePayload) = await SendSingleRequestAsync(
                        treeDisconnectHeader,
                        treeDisconnectRequest.ToByteArray(),
                        cancellationToken).ConfigureAwait(false);
                    _Session.ApplyTreeDisconnectResult(
                        treeHandle.TreeId,
                        treeDisconnectResponseHeader.Status,
                        Smb2TreeDisconnectResponse.ReadFrom(treeDisconnectResponsePayload));
                    MarkTreeDisconnected(treeHandle);
                }

                if (_Session.IsAuthenticated)
                {
                    Smb2LogoffRequest logoffRequest = _Session.CreateLogoffRequest();
                    Smb2Header logoffHeader = _Session.CreateRequestHeader(Smb2Command.Logoff, sessionId: _Session.SessionId!.Value);
                    (Smb2Header logoffResponseHeader, byte[] logoffResponsePayload) = await SendSingleRequestAsync(
                        logoffHeader,
                        logoffRequest.ToByteArray(),
                        cancellationToken).ConfigureAwait(false);
                    _Session.ApplyLogoffResult(
                        logoffResponseHeader.Status,
                        ReadSuccessResponseOrDefault(logoffResponseHeader.Status, logoffResponsePayload, Smb2LogoffResponse.ReadFrom));
                }
            }
            finally
            {
                await ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
            }
        }

        private async Task NegotiateAsync(CancellationToken cancellationToken)
        {
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Negotiate);
            Smb2NegotiateRequest request = _Session.CreateNegotiateRequest();
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);

            if (responseHeader.Status != NtStatus.Success)
            {
                throw OpenCifsStatusException.CreateFromResponsePayload(
                    Smb2Command.Negotiate,
                    responseHeader.Status,
                    responsePayload);
            }

            _Session.ApplyNegotiateResponse(Smb2NegotiateResponse.ReadFrom(responsePayload));
        }

        private async Task<(Smb2Header ResponseHeader, byte[] ResponsePayload)> SendOpenExistingCreateAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken,
            Smb2OplockLevel requestedOplockLevel,
            bool requestDurableHandle,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey)
        {
            Smb2CreateRequest request = _Session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess: desiredAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: createOptions,
                requestedOplockLevel: requestedOplockLevel,
                requestDurableHandle: requestDurableHandle,
                requestedLeaseState: requestedLeaseState,
                leaseKey: leaseKey);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            return await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
        }

        private OpenCifsClientOpenHandle CreateOpenHandle(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            Smb2Header responseHeader,
            Smb2CreateResponse createResponse,
            bool isDirectory,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel)
        {
            OpenState openState = _Session.ApplyCreateResult(treeHandle.TreeId, path, responseHeader.Status, createResponse);
            OpenCifsClientOpenHandle openHandle = new OpenCifsClientOpenHandle(
                _ConnectionId,
                _SessionGeneration,
                treeHandle,
                openState.PersistentFileId,
                openState.VolatileFileId,
                openState.Path,
                isDirectory,
                openState.OplockLevel,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                openState.IsDurable,
                openState.LeaseKey,
                openState.LeaseState);
            _ActiveOpensByKey[GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId)] = openHandle;
            return openHandle;
        }

        private async Task ApplySetInfoAsync(OpenCifsClientOpenHandle openHandle, Smb2SetInfoRequest request, CancellationToken cancellationToken)
        {
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.SetInfo, openHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplySetInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2SetInfoResponse.ReadFrom));
        }

        private async Task EnsureCreditsAsync(ushort requiredCredits, CancellationToken cancellationToken)
        {
            while (_Session.AvailableCredits < requiredCredits)
            {
                int previousCredits = _Session.AvailableCredits;
                await RequestCreditWindowGrowthAsync(requiredCredits, cancellationToken).ConfigureAwait(false);

                if (_Session.AvailableCredits <= previousCredits)
                {
                    throw new InvalidOperationException("The SMB2 credit window could not be expanded enough for the requested operation.");
                }
            }
        }

        private async Task RequestCreditWindowGrowthAsync(ushort requestedCredits, CancellationToken cancellationToken)
        {
            EnsureAuthenticatedSession();
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Echo, creditRequest: requestedCredits, sessionId: _Session.SessionId!.Value);
            Smb2EchoRequest request = _Session.CreateEchoRequest();
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyEchoResult(
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2EchoResponse.ReadFrom));
        }

        private async Task<(Smb2Header ResponseHeader, byte[] ResponsePayload, bool CancelledByClient)> SendChangeNotifyRequestAsync(
            Smb2Header requestHeader,
            byte[] requestPayload,
            CancellationToken cancellationToken)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (requestPayload == null)
            {
                throw new ArgumentNullException(nameof(requestPayload), "RequestPayload cannot be null.");
            }

            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(requestHeader, requestPayload)
            });

            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(requestPacket), cancellationToken).ConfigureAwait(false);

            bool cancellationRequested = false;
            bool cancelIssued = false;
            bool pendingResponseObserved = false;

            while (true)
            {
                byte[] responseBytes;

                try
                {
                    responseBytes = await _Connection.ReadAsync(cancellationRequested ? CancellationToken.None : cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationRequested && cancellationToken.IsCancellationRequested)
                {
                    cancellationRequested = true;

                     if (pendingResponseObserved && !cancelIssued)
                     {
                         await WriteCancelRequestAsync(requestHeader.MessageId).ConfigureAwait(false);
                         cancelIssued = true;
                     }

                    continue;
                }

                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                _Session.ValidateResponsePacket(responsePacket, responseBytes);

                if (responsePacket.Entries.Count != 1)
                {
                    throw new ProtocolValidationException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new ProtocolValidationException("The server response command does not match the request command.");
                }

                _Session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new ProtocolValidationException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
                    }

                    pendingResponseObserved = true;

                    if (cancellationRequested && !cancelIssued)
                    {
                        await WriteCancelRequestAsync(requestHeader.MessageId).ConfigureAwait(false);
                        cancelIssued = true;
                    }

                    continue;
                }

                byte[] responsePayload = GetResponsePayloadBytes(responseEntry);
                return (responseEntry.Header, responsePayload, cancelIssued && responseEntry.Header.Status == NtStatus.Cancelled);
            }
        }

        private async Task<(Smb2Header ResponseHeader, byte[] ResponsePayload)> SendSingleRequestAsync(
            Smb2Header requestHeader,
            byte[] requestPayload,
            CancellationToken cancellationToken)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (requestPayload == null)
            {
                throw new ArgumentNullException(nameof(requestPayload), "RequestPayload cannot be null.");
            }

            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(requestHeader, requestPayload)
            });

            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(requestPacket), cancellationToken).ConfigureAwait(false);

            while (true)
            {
                byte[] responseBytes = await _Connection.ReadAsync(cancellationToken).ConfigureAwait(false);
                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                if (requestHeader.Command != Smb2Command.SessionSetup)
                {
                    _Session.ValidateResponsePacket(responsePacket, responseBytes);
                }

                if (responsePacket.Entries.Count != 1)
                {
                    throw new ProtocolValidationException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new ProtocolValidationException("The server response command does not match the request command.");
                }

                _Session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new ProtocolValidationException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
                    }

                    continue;
                }

                if (!ResponseCarriesCommandPayload(responseEntry.Header))
                {
                    return (responseEntry.Header, (byte[])responseEntry.Payload.Clone());
                }

                return (responseEntry.Header, GetResponsePayloadBytes(responseEntry));
            }
        }

        private async Task WriteCancelRequestAsync(ulong pendingMessageId)
        {
            if (_Connection == null)
            {
                throw new InvalidOperationException("The client connection is not connected.");
            }

            Smb2Header cancelHeader = _Session.CreateCancelRequestHeader(pendingMessageId);
            Smb2CancelRequest cancelRequest = _Session.CreateCancelRequest();
            Smb2CompoundPacket cancelPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(cancelHeader, cancelRequest.ToByteArray())
            });
            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(cancelPacket), CancellationToken.None).ConfigureAwait(false);
        }

        private static byte[] GetResponsePayloadBytes(Smb2CompoundPacketEntry responseEntry)
        {
            if (!ResponseCarriesCommandPayload(responseEntry.Header))
            {
                return (byte[])responseEntry.Payload.Clone();
            }

            try
            {
                return Smb2CompoundPayloadHelper.TrimResponsePayload(responseEntry.Header.Command, responseEntry.Payload);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new InvalidOperationException(
                    "The server response payload could not be trimmed for command " +
                    responseEntry.Header.Command +
                    " with status " +
                    responseEntry.Header.Status +
                    " and " +
                    responseEntry.Payload.Length +
                    " payload bytes.",
                    exception);
            }
        }

        private OpenCifsClientOpenHandle GetTrackedOpenHandle(ulong persistentFileId, ulong volatileFileId)
        {
            if (!_ActiveOpensByKey.TryGetValue(GetOpenKey(persistentFileId, volatileFileId), out OpenCifsClientOpenHandle? openHandle))
            {
                throw new InvalidOperationException("The unsolicited SMB2 oplock-break notification does not match a tracked client open handle.");
            }

            return openHandle;
        }

        private static TResponse ReadSuccessResponseOrDefault<TResponse>(
            NtStatus status,
            byte[] responsePayload,
            Func<ReadOnlyMemory<byte>, TResponse> readFrom)
            where TResponse : class, new()
        {
            if (status != NtStatus.Success)
            {
                return new TResponse();
            }

            return readFrom(responsePayload);
        }

        private static bool ResponseCarriesCommandPayload(Smb2Header responseHeader)
        {
            if (responseHeader == null)
            {
                throw new ArgumentNullException(nameof(responseHeader), "ResponseHeader cannot be null.");
            }

            if (responseHeader.Status == NtStatus.Success)
            {
                return true;
            }

            return responseHeader.Command == Smb2Command.SessionSetup &&
                responseHeader.Status == NtStatus.MoreProcessingRequired;
        }

        private void EnsureNegotiatedConnection()
        {
            ThrowIfDisposed();

            if (_Connection == null || !_Session.IsNegotiated)
            {
                throw new InvalidOperationException("A negotiated direct-TCP connection is required before authenticating.");
            }
        }

        private void EnsureAuthenticatedSession()
        {
            ThrowIfDisposed();

            if (_Connection == null || !_Session.IsAuthenticated || _Session.SessionId == null)
            {
                throw new InvalidOperationException("An authenticated direct-TCP session is required before issuing low-level client operations.");
            }
        }

        private void ValidateTreeHandle(OpenCifsClientTreeHandle treeHandle)
        {
            EnsureAuthenticatedSession();

            if (treeHandle == null)
            {
                throw new ArgumentNullException(nameof(treeHandle), "TreeHandle cannot be null.");
            }

            if (treeHandle.ConnectionId != _ConnectionId || treeHandle.SessionGeneration != _SessionGeneration)
            {
                throw new InvalidOperationException("The specified tree handle does not belong to the current client connection lifecycle.");
            }

            if (treeHandle.IsDisconnected)
            {
                throw new InvalidOperationException("The specified tree handle has already been disconnected.");
            }

            if (!_ActiveTreesById.TryGetValue(treeHandle.TreeId, out OpenCifsClientTreeHandle? trackedTreeHandle) || !ReferenceEquals(trackedTreeHandle, treeHandle))
            {
                throw new InvalidOperationException("The specified tree handle is no longer active on this client connection.");
            }
        }

        private void ValidateOpenHandle(OpenCifsClientOpenHandle openHandle)
        {
            EnsureAuthenticatedSession();

            if (openHandle == null)
            {
                throw new ArgumentNullException(nameof(openHandle), "OpenHandle cannot be null.");
            }

            if (openHandle.ConnectionId != _ConnectionId || openHandle.SessionGeneration != _SessionGeneration)
            {
                throw new InvalidOperationException("The specified open handle does not belong to the current client connection lifecycle.");
            }

            if (openHandle.IsClosed)
            {
                throw new InvalidOperationException("The specified open handle has already been closed.");
            }

            ValidateTreeHandle(openHandle.TreeHandle);
            string key = GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId);

            if (!_ActiveOpensByKey.TryGetValue(key, out OpenCifsClientOpenHandle? trackedOpenHandle) || !ReferenceEquals(trackedOpenHandle, openHandle))
            {
                throw new InvalidOperationException("The specified open handle is no longer active on this client connection.");
            }
        }

        private void ValidateFileOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (openHandle.IsDirectory)
            {
                throw new InvalidOperationException(operationName + " requires a file open.");
            }
        }

        private void ValidateDirectoryOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (!openHandle.IsDirectory)
            {
                throw new InvalidOperationException(operationName + " requires a directory open.");
            }
        }

        private void RemoveOpenHandle(OpenCifsClientOpenHandle openHandle)
        {
            string key = GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId);
            _ActiveOpensByKey.Remove(key);
            openHandle.InvalidateDurableReconnect();
            openHandle.MarkClosed();
        }

        private void MarkTreeDisconnected(OpenCifsClientTreeHandle treeHandle)
        {
            treeHandle.MarkDisconnected();
            _ActiveTreesById.Remove(treeHandle.TreeId);

            List<OpenCifsClientOpenHandle> openHandles = new List<OpenCifsClientOpenHandle>();

            foreach (OpenCifsClientOpenHandle trackedOpenHandle in _ActiveOpensByKey.Values)
            {
                if (trackedOpenHandle.TreeId == treeHandle.TreeId)
                {
                    openHandles.Add(trackedOpenHandle);
                }
            }

            for (int index = 0; index < openHandles.Count; index++)
            {
                RemoveOpenHandle(openHandles[index]);
            }
        }

        private void ThrowIfDisposed()
        {
            if (_Disposed || _AsyncDisposed)
            {
                throw new ObjectDisposedException(nameof(OpenCifsClientConnection), "The client connection has been disposed.");
            }
        }

        private void ResetSession(bool invalidateDurableReconnect = true)
        {
            InvalidateTrackedHandles(invalidateDurableReconnect);
            _SessionGeneration++;
            _Session = new OpenCifsClientSession(Options);
        }

        private void InvalidateTrackedHandles(bool invalidateDurableReconnect)
        {
            foreach (OpenCifsClientOpenHandle openHandle in _ActiveOpensByKey.Values)
            {
                if (invalidateDurableReconnect)
                {
                    openHandle.InvalidateDurableReconnect();
                }

                openHandle.MarkClosed();
            }

            foreach (OpenCifsClientTreeHandle treeHandle in _ActiveTreesById.Values)
            {
                treeHandle.MarkDisconnected();
            }

            _ActiveOpensByKey.Clear();
            _ActiveTreesById.Clear();
        }

        private async Task ResetTransportAsync()
        {
            FramedPipeConnection? connection = _Connection;
            TcpClient? tcpClient = _TcpClient;
            _Connection = null;
            _TcpClient = null;

            if (connection != null)
            {
                try
                {
                    connection.CompleteWrites();
                }
                catch (ObjectDisposedException)
                {
                }
                catch (InvalidOperationException)
                {
                }

                await connection.DisposeAsync().ConfigureAwait(false);
            }

            if (tcpClient != null)
            {
                tcpClient.Dispose();
            }
        }

        private static string GetOpenKey(ulong persistentFileId, ulong volatileFileId)
        {
            return persistentFileId.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                ":" +
                volatileFileId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        private static string NormalizeRelativePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            return path.Replace('/', '\\').TrimStart('\\');
        }

        private readonly Dictionary<uint, OpenCifsClientTreeHandle> _ActiveTreesById = new Dictionary<uint, OpenCifsClientTreeHandle>();
        private readonly Dictionary<string, OpenCifsClientOpenHandle> _ActiveOpensByKey = new Dictionary<string, OpenCifsClientOpenHandle>(StringComparer.Ordinal);
        private readonly Guid _ConnectionId = Guid.NewGuid();
        private OpenCifsClientSession _Session;
        private FramedPipeConnection? _Connection;
        private TcpClient? _TcpClient;
        private long _SessionGeneration;
        private bool _Disposed;
        private bool _AsyncDisposed;
    }
}

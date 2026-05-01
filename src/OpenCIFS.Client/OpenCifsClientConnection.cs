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
        private const uint DefaultPipeTransceiveOutputLength = 65536;
        private const ulong RelatedCompoundFileId = UInt64.MaxValue;
        private const string IpcShareName = "IPC$";
        private const string SrvsvcPipeName = "srvsvc";

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
                throw new OpenCifsClientStateException("The client connection is already connected.");
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
        /// Connect and negotiate against the configured direct-TCP endpoint and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryConnectAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ConnectAsync(cancellationToken));
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
        /// Connect, negotiate, and authenticate against the configured direct-TCP endpoint and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryConnectAndAuthenticateAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ConnectAndAuthenticateAsync(credential, cancellationToken));
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
                throw new OpenCifsClientStateException("The client connection is already authenticated.");
            }

            try
            {
                Smb2Header challengeHeader = _Session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                Smb2SessionSetupRequest initialRequest = _Session.CreateSessionSetupRequest(credential);
                byte[] initialRequestBody = initialRequest.ToByteArray();
                _Session.AppendPreauthMessageBytes(challengeHeader, initialRequestBody);
                (Smb2Header challengeResponseHeader, byte[] challengeResponsePayload) = await SendSingleRequestAsync(
                    challengeHeader,
                    initialRequestBody,
                    cancellationToken).ConfigureAwait(false);

                if (challengeResponseHeader.Status != NtStatus.MoreProcessingRequired)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(
                        Smb2Command.SessionSetup,
                        challengeResponseHeader.Status,
                        challengeResponsePayload);
                }

                _Session.AppendPreauthMessageBytes(challengeResponseHeader, challengeResponsePayload);
                Smb2SessionSetupResponse challengeResponse = Smb2SessionSetupResponse.ReadFrom(challengeResponsePayload);
                Smb2SessionSetupRequest authenticateRequest = _Session.CreateSessionAuthenticateRequest(
                    credential,
                    challengeResponseHeader.SessionId,
                    challengeResponseHeader.Status,
                    challengeResponse);
                Smb2Header authenticateHeader = _Session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResponseHeader.SessionId);
                byte[] authenticateRequestBody = authenticateRequest.ToByteArray();
                _Session.AppendPreauthMessageBytes(authenticateHeader, authenticateRequestBody);
                (Smb2Header authenticateResponseHeader, byte[] authenticateResponsePayload) = await SendSingleRequestAsync(
                    authenticateHeader,
                    authenticateRequestBody,
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
        /// Authenticate the active direct-TCP session and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryAuthenticateAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => AuthenticateAsync(credential, cancellationToken));
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
        /// Send an authenticated SMB2 echo request and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryEchoAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => EchoAsync(cancellationToken));
        }

        /// <summary>
        /// Enumerate remote shares through the OpenCIFS client path using IPC$ and the SRVSVC named-pipe endpoint.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Remote share entries.</returns>
        public async Task<OpenCifsRemoteShareInfo[]> EnumerateRemoteSharesAsync(CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();
            OpenCifsClientTreeHandle ipcTreeHandle = await TreeConnectAsync(IpcShareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await OpenAsync(
                    ipcTreeHandle,
                    SrvsvcPipeName,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                await BindSrvsvcAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
                return await EnumerateSrvsvcSharesAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (pipeHandle != null && !pipeHandle.IsClosed)
                {
                    try
                    {
                        await CloseAsync(pipeHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }

                if (!ipcTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await TreeDisconnectAsync(ipcTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Enumerate remote shares through IPC$ and SRVSVC without throwing for typed client failures.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsRemoteShareInfo[]>> TryEnumerateRemoteSharesAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => EnumerateRemoteSharesAsync(cancellationToken));
        }

        /// <summary>
        /// Query bounded detailed information for a single remote share through IPC$ and the SRVSVC named-pipe endpoint.
        /// </summary>
        /// <param name="shareName">Remote share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Detailed remote share information.</returns>
        public async Task<OpenCifsRemoteShareInfo> GetRemoteShareInfoAsync(string shareName, CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            string normalizedShareName = shareName.Trim();
            OpenCifsClientTreeHandle ipcTreeHandle = await TreeConnectAsync(IpcShareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await OpenAsync(
                    ipcTreeHandle,
                    SrvsvcPipeName,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                await BindSrvsvcAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
                return await GetSrvsvcShareInfoAsync(pipeHandle, normalizedShareName, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (pipeHandle != null && !pipeHandle.IsClosed)
                {
                    try
                    {
                        await CloseAsync(pipeHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }

                if (!ipcTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await TreeDisconnectAsync(ipcTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Query bounded detailed information for a single remote share without throwing for typed client failures.
        /// </summary>
        /// <param name="shareName">Remote share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsRemoteShareInfo>> TryGetRemoteShareInfoAsync(string shareName, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => GetRemoteShareInfoAsync(shareName, cancellationToken));
        }

        /// <summary>
        /// Query bounded DFS referrals through the OpenCIFS IPC$ / connection-scoped IOCTL path.
        /// </summary>
        /// <param name="dfsPath">DFS path such as <c>\server\share\link</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Returned DFS referral entries.</returns>
        public async Task<OpenCifsDfsReferral[]> GetDfsReferralsAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();
            string normalizedDfsPath = NormalizeDfsPath(dfsPath);
            OpenCifsClientTreeHandle ipcTreeHandle = await TreeConnectAsync(IpcShareName, cancellationToken).ConfigureAwait(false);

            try
            {
                Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Ioctl, ipcTreeHandle.TreeId, sessionId: _Session.SessionId!.Value);
                Smb2IoctlRequest request = _Session.CreateConnectionIoctlRequest(
                    (uint)FsctlCode.DfsGetReferrals,
                    new DfsReferralRequest
                    {
                        MaxReferralLevel = 2,
                        RequestPath = normalizedDfsPath
                    }.ToByteArray(),
                    maxOutputResponse: DefaultPipeTransceiveOutputLength,
                    maxInputResponse: 0,
                    flags: Smb2IoctlFlags.IsFsctl);
                (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);

                if (responseHeader.Status != NtStatus.Success)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(Smb2Command.Ioctl, responseHeader.Status, responsePayload);
                }

                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(responsePayload);

                if (ioctlResponse.CtlCode != (uint)FsctlCode.DfsGetReferrals)
                {
                    throw new OpenCifsClientProtocolException("The server IOCTL response does not contain an FSCTL_DFS_GET_REFERRALS payload.");
                }

                DfsReferralResponse referralResponse;

                try
                {
                    referralResponse = DfsReferralResponse.ReadFrom(ioctlResponse.OutputBuffer);
                }
                catch (ProtocolEncodingException exception)
                {
                    throw new OpenCifsClientProtocolException("The server DFS referral payload is malformed.", exception);
                }

                OpenCifsDfsReferral[] referrals = ConvertDfsReferralResponse(normalizedDfsPath, referralResponse);
                UpdateDfsReferralCache(referrals);
                return referrals;
            }
            finally
            {
                if (!ipcTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await TreeDisconnectAsync(ipcTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Query bounded DFS referrals without throwing for typed client failures.
        /// </summary>
        /// <param name="dfsPath">DFS path such as <c>\server\share\link</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsDfsReferral[]>> TryGetDfsReferralsAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => GetDfsReferralsAsync(dfsPath, cancellationToken));
        }

        /// <summary>
        /// Resolve a bounded DFS path to a concrete target UNC path, using a referral cache when possible.
        /// </summary>
        /// <param name="dfsPath">DFS path such as <c>\server\share\link\file.txt</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Resolved DFS target path.</returns>
        public async Task<OpenCifsResolvedDfsPath> ResolveDfsPathAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();
            string normalizedDfsPath = NormalizeDfsPath(dfsPath);

            if (TryResolveDfsPathFromCache(normalizedDfsPath, out OpenCifsResolvedDfsPath? cachedResolution) && cachedResolution != null)
            {
                return cachedResolution;
            }

            OpenCifsDfsReferral[] referrals = await GetDfsReferralsAsync(normalizedDfsPath, cancellationToken).ConfigureAwait(false);
            return CreateResolvedDfsPath(normalizedDfsPath, referrals, wasResolvedFromCache: false);
        }

        /// <summary>
        /// Resolve a bounded DFS path without throwing for typed client failures.
        /// </summary>
        /// <param name="dfsPath">DFS path such as <c>\server\share\link\file.txt</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsResolvedDfsPath>> TryResolveDfsPathAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ResolveDfsPathAsync(dfsPath, cancellationToken));
        }

        /// <summary>
        /// Transceive a byte buffer through a remote named pipe hosted under <c>IPC$</c>.
        /// </summary>
        /// <param name="pipeName">Named-pipe endpoint name.</param>
        /// <param name="inputBuffer">Request payload.</param>
        /// <param name="maxOutputResponse">Maximum response payload length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Response payload.</returns>
        public async Task<byte[]> TransceiveNamedPipeAsync(
            string pipeName,
            byte[] inputBuffer,
            uint maxOutputResponse = DefaultPipeTransceiveOutputLength,
            CancellationToken cancellationToken = default)
        {
            EnsureAuthenticatedSession();

            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer), "InputBuffer cannot be null.");
            }

            string normalizedPipeName = NormalizePipeName(pipeName);

            if (maxOutputResponse == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxOutputResponse), "MaxOutputResponse must be greater than zero.");
            }

            OpenCifsClientTreeHandle ipcTreeHandle = await TreeConnectAsync(IpcShareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await OpenAsync(
                    ipcTreeHandle,
                    normalizedPipeName,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return await PipeTransceiveAsync(pipeHandle, inputBuffer, maxOutputResponse, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (pipeHandle != null && !pipeHandle.IsClosed)
                {
                    try
                    {
                        await CloseAsync(pipeHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }

                if (!ipcTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await TreeDisconnectAsync(ipcTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Transceive a byte buffer through a remote named pipe under <c>IPC$</c> without throwing for typed client failures.
        /// </summary>
        /// <param name="pipeName">Named-pipe endpoint name.</param>
        /// <param name="inputBuffer">Request payload.</param>
        /// <param name="maxOutputResponse">Maximum response payload length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryTransceiveNamedPipeAsync(
            string pipeName,
            byte[] inputBuffer,
            uint maxOutputResponse = DefaultPipeTransceiveOutputLength,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => TransceiveNamedPipeAsync(pipeName, inputBuffer, maxOutputResponse, cancellationToken));
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
        /// Expand the authenticated SMB2 credit window and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<int>> TryRequestMaximumCreditsAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => RequestMaximumCreditsAsync(cancellationToken));
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
            Smb2TreeConnectResponse treeConnectResponse = ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2TreeConnectResponse.ReadFrom);
            _Session.ApplyTreeConnectResult(
                normalizedShareName,
                responseHeader.TreeId,
                responseHeader.Status,
                treeConnectResponse);

            if (ShouldValidateSecureNegotiate() && !_Session.IsSecureNegotiateValidated)
            {
                try
                {
                    await ValidateSecureNegotiateCoreAsync(responseHeader.TreeId, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await ResetTransportAsync().ConfigureAwait(false);
                    ResetSession();
                    throw;
                }
            }

            OpenCifsClientTreeHandle handle = new OpenCifsClientTreeHandle(
                _ConnectionId,
                _SessionGeneration,
                normalizedShareName,
                responseHeader.TreeId,
                (Smb2ShareFlags)treeConnectResponse.ShareFlags);
            _ActiveTreesById[handle.TreeId] = handle;
            return handle;
        }

        /// <summary>
        /// Connect a tree for the specified share name and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientTreeHandle>> TryTreeConnectAsync(string shareName, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => TreeConnectAsync(shareName, cancellationToken));
        }

        /// <summary>
        /// Run a bounded SMB3 secure-negotiate validation round trip on an existing tree connection.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task ValidateSecureNegotiateAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);

            if (!ShouldValidateSecureNegotiate())
            {
                return;
            }

            try
            {
                await ValidateSecureNegotiateCoreAsync(treeHandle.TreeId, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
                throw;
            }
        }

        /// <summary>
        /// Run a bounded SMB3 secure-negotiate validation round trip and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryValidateSecureNegotiateAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ValidateSecureNegotiateAsync(treeHandle, cancellationToken));
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
        /// Disconnect a previously connected tree handle and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryTreeDisconnectAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => TreeDisconnectAsync(treeHandle, cancellationToken));
        }

        /// <summary>
        /// Execute a bounded related-compound create, query-info, and close flow against an existing tree.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="informationClass">Requested file-information class.</param>
        /// <param name="outputBufferLength">Maximum response buffer length.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition for the create leg.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded query-info output buffer.</returns>
        public async Task<byte[]> CompoundCreateQueryInfoCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            uint desiredAccess = DefaultDesiredAccess,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.Open,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            await EnsureCreditsAsync(requiredCredits: 3, cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = _Session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                FileAttributes.Normal,
                shareAccess,
                createDisposition,
                createOptions);
            Smb2QueryInfoRequest queryRequest = CreateRelatedQueryInfoRequest(informationClass, outputBufferLength);
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            Smb2Header queryHeader = _Session.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: _Session.SessionId!.Value);
            Smb2Header closeHeader = _Session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: _Session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(queryHeader, queryRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 3);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry queryEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[2];
            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(createEntry.Header.Status, GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2QueryInfoResponse queryResponse = ReadSuccessResponseOrDefault(queryEntry.Header.Status, GetResponsePayloadBytes(queryEntry), Smb2QueryInfoResponse.ReadFrom);
            Smb2CloseResponse closeResponse = ReadSuccessResponseOrDefault(closeEntry.Header.Status, GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            byte[] outputBuffer = Array.Empty<byte>();

            try
            {
                openState = _Session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    outputBuffer = _Session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, queryEntry.Header.Status, queryResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    _Session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return outputBuffer;
        }

        /// <summary>
        /// Execute a bounded related-compound create, query-info, and close flow and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="informationClass">Requested file-information class.</param>
        /// <param name="outputBufferLength">Maximum response buffer length.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition for the create leg.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryCompoundCreateQueryInfoCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            uint desiredAccess = DefaultDesiredAccess,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.Open,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CompoundCreateQueryInfoCloseAsync(
                treeHandle,
                path,
                informationClass,
                outputBufferLength,
                desiredAccess,
                shareAccess,
                createDisposition,
                createOptions,
                cancellationToken));
        }

        /// <summary>
        /// Execute a bounded related-compound open, read, and close flow against an existing tree.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="length">Requested read length.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="minimumCount">Minimum read length.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Read data.</returns>
        public async Task<byte[]> CompoundOpenReadCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint length,
            ulong offset = 0,
            uint minimumCount = 0,
            uint desiredAccess = 0x80000000U,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            ushort readCredits = _Session.GetRequiredReadWriteCredits(length);
            ushort readCreditCharge = _Session.GetReadWriteCreditCharge(length);
            await EnsureCreditsAsync(checked((ushort)(2 + readCredits)), cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = _Session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                FileAttributes.Normal,
                shareAccess,
                Smb2CreateDisposition.Open,
                createOptions);
            Smb2ReadRequest readRequest = CreateRelatedReadRequest(length, offset, minimumCount);
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            Smb2Header readHeader = _Session.CreateRequestHeader(
                Smb2Command.Read,
                creditRequest: readCredits,
                sessionId: _Session.SessionId!.Value,
                creditCharge: readCreditCharge);
            readHeader.Flags |= Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(readHeader);
            Smb2Header closeHeader = _Session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: _Session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(readHeader, readRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 3);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry readEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[2];
            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(createEntry.Header.Status, GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2ReadResponse readResponse = ReadSuccessResponseOrDefault(readEntry.Header.Status, GetResponsePayloadBytes(readEntry), Smb2ReadResponse.ReadFrom);
            Smb2CloseResponse closeResponse = ReadSuccessResponseOrDefault(closeEntry.Header.Status, GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            byte[] data = Array.Empty<byte>();

            try
            {
                openState = _Session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    data = _Session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readEntry.Header.Status, readResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    _Session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return data;
        }

        /// <summary>
        /// Execute a bounded related-compound open, read, and close flow and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="length">Requested read length.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="minimumCount">Minimum read length.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryCompoundOpenReadCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint length,
            ulong offset = 0,
            uint minimumCount = 0,
            uint desiredAccess = 0x80000000U,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CompoundOpenReadCloseAsync(
                treeHandle,
                path,
                length,
                offset,
                minimumCount,
                desiredAccess,
                shareAccess,
                createOptions,
                cancellationToken));
        }

        /// <summary>
        /// Execute a bounded related-compound create, write, flush, and close flow against an existing tree.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="fileAttributes">Create-time file attributes.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition for the create leg.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Acknowledged write length.</returns>
        public async Task<uint> CompoundCreateWriteFlushCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            byte[] data,
            uint desiredAccess = DefaultDesiredAccess,
            FileAttributes fileAttributes = FileAttributes.Normal,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.OverwriteIf,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            ushort writeCredits = _Session.GetRequiredReadWriteCredits(checked((uint)data.Length));
            ushort writeCreditCharge = _Session.GetReadWriteCreditCharge(checked((uint)data.Length));
            await EnsureCreditsAsync(checked((ushort)(3 + writeCredits)), cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = _Session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions);
            Smb2WriteRequest writeRequest = CreateRelatedWriteRequest(data, offset: 0);
            Smb2FlushRequest flushRequest = CreateRelatedFlushRequest();
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = _Session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            Smb2Header writeHeader = _Session.CreateRequestHeader(
                Smb2Command.Write,
                creditRequest: writeCredits,
                sessionId: _Session.SessionId!.Value,
                creditCharge: writeCreditCharge);
            writeHeader.Flags |= Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(writeHeader);
            Smb2Header flushHeader = _Session.CreateRelatedRequestHeader(Smb2Command.Flush, sessionId: _Session.SessionId!.Value);
            Smb2Header closeHeader = _Session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: _Session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(writeHeader, writeRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(flushHeader, flushRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 4);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry writeEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry flushEntry = responsePacket.Entries[2];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[3];
            Smb2CreateResponse createResponse = ReadSuccessResponseOrDefault(createEntry.Header.Status, GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2WriteResponse writeResponse = ReadSuccessResponseOrDefault(writeEntry.Header.Status, GetResponsePayloadBytes(writeEntry), Smb2WriteResponse.ReadFrom);
            Smb2FlushResponse flushResponse = ReadSuccessResponseOrDefault(flushEntry.Header.Status, GetResponsePayloadBytes(flushEntry), Smb2FlushResponse.ReadFrom);
            Smb2CloseResponse closeResponse = ReadSuccessResponseOrDefault(closeEntry.Header.Status, GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            uint writtenCount = 0;

            try
            {
                openState = _Session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    writtenCount = _Session.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeEntry.Header.Status, writeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }

                try
                {
                    _Session.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, flushEntry.Header.Status, flushResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    _Session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return writtenCount;
        }

        /// <summary>
        /// Execute a bounded related-compound create, write, flush, and close flow and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="desiredAccess">Desired access mask for the create leg.</param>
        /// <param name="fileAttributes">Create-time file attributes.</param>
        /// <param name="shareAccess">Requested share-access mask.</param>
        /// <param name="createDisposition">Create disposition for the create leg.</param>
        /// <param name="createOptions">Create options for the create leg.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<uint>> TryCompoundCreateWriteFlushCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            byte[] data,
            uint desiredAccess = DefaultDesiredAccess,
            FileAttributes fileAttributes = FileAttributes.Normal,
            uint shareAccess = DefaultShareAccess,
            Smb2CreateDisposition createDisposition = Smb2CreateDisposition.OverwriteIf,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CompoundCreateWriteFlushCloseAsync(
                treeHandle,
                path,
                data,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                cancellationToken));
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
        /// <param name="requestDurableHandle">Whether to request a durable open for the negotiated dialect.</param>
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
                request,
                (createOptions & Smb2CreateOptions.DirectoryFile) != 0,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                effectiveOplockLevel);
        }

        /// <summary>
        /// Create or open a path under a connected tree and preserve typed client failures in a non-throwing result envelope.
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
        /// <param name="requestDurableHandle">Whether to request a durable open for the negotiated dialect.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key. When omitted, a random key is generated.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientOpenHandle>> TryOpenAsync(
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
            return OpenCifsClientResultFactory.TryAsync(() => OpenAsync(
                treeHandle,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                cancellationToken,
                requestedOplockLevel,
                requestDurableHandle,
                requestedLeaseState,
                leaseKey));
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
                null,
                isDirectory,
                desiredAccess,
                FileAttributes.Normal,
                DefaultShareAccess,
                Smb2CreateDisposition.Open,
                appliedCreateOptions,
                effectiveOplockLevel);
        }

        /// <summary>
        /// Open an existing path and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Tracked tree handle.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="desiredAccess">Desired access mask.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="requestedOplockLevel">Requested oplock level.</param>
        /// <param name="requestDurableHandle">Whether to request a bounded SMB 2.0.2 durable open.</param>
        /// <param name="requestedLeaseState">Requested SMB 2.1 lease state when <paramref name="requestedOplockLevel"/> is <see cref="Smb2OplockLevel.Lease"/>.</param>
        /// <param name="leaseKey">Optional 16-byte SMB 2.1 lease key. When omitted, a random key is generated.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientOpenHandle>> TryOpenExistingPathAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess = DefaultDesiredAccess,
            CancellationToken cancellationToken = default,
            Smb2OplockLevel requestedOplockLevel = Smb2OplockLevel.None,
            bool requestDurableHandle = false,
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.None,
            byte[]? leaseKey = null)
        {
            return OpenCifsClientResultFactory.TryAsync(() => OpenExistingPathAsync(
                treeHandle,
                path,
                desiredAccess,
                cancellationToken,
                requestedOplockLevel,
                requestDurableHandle,
                requestedLeaseState,
                leaseKey));
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
                throw new OpenCifsClientStateException("The specified open handle is not currently usable as a durable reconnect token.");
            }

            if (durableOpenHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException("Durable reconnect is bounded to file opens in the current managed slice.");
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
                durableOpenHandle.LeaseKey.Length == 16 ? durableOpenHandle.LeaseKey : null,
                durableOpenHandle.DurableCreateGuid,
                durableOpenHandle.UsesDurableHandleV2);
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
                request,
                isDirectory: false,
                durableOpenHandle.DesiredAccess,
                durableOpenHandle.FileAttributes,
                durableOpenHandle.ShareAccess,
                durableOpenHandle.CreateDisposition,
                durableOpenHandle.CreateOptions,
                durableOpenHandle.RequestedOplockLevel);
        }

        /// <summary>
        /// Re-establish a previously granted durable open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="treeHandle">Connected tree handle on the new session.</param>
        /// <param name="durableOpenHandle">Handle from the original connection lifecycle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientOpenHandle>> TryReconnectDurableOpenAsync(
            OpenCifsClientTreeHandle treeHandle,
            OpenCifsClientOpenHandle durableOpenHandle,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ReconnectDurableOpenAsync(treeHandle, durableOpenHandle, cancellationToken));
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
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
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
        /// Wait for the next unsolicited SMB2 oplock-break notification and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientOplockBreakNotification>> TryWaitForOplockBreakAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WaitForOplockBreakAsync(cancellationToken));
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
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
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
        /// Wait for the next unsolicited SMB2 lease-break notification and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientLeaseBreakNotification>> TryWaitForLeaseBreakAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WaitForLeaseBreakAsync(cancellationToken));
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
        /// Read a byte range from an existing file open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="length">Requested read length.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="minimumCount">Minimum read length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryReadAsync(
            OpenCifsClientOpenHandle openHandle,
            uint length,
            ulong offset,
            uint minimumCount = 0,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ReadAsync(openHandle, length, offset, minimumCount, cancellationToken));
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
        /// Write a byte buffer to an existing file open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="offset">Byte offset.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<uint>> TryWriteAsync(OpenCifsClientOpenHandle openHandle, byte[] data, ulong offset, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WriteAsync(openHandle, data, offset, cancellationToken));
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
        /// Flush an existing file open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryFlushAsync(OpenCifsClientOpenHandle openHandle, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => FlushAsync(openHandle, cancellationToken));
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
        /// Apply one or more byte-range lock or unlock elements and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="locks">Requested lock elements.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryLockAsync(OpenCifsClientOpenHandle openHandle, Smb2LockElement[] locks, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => LockAsync(openHandle, locks, cancellationToken));
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
        /// Query file information for an existing open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="informationClass">Requested file-information class.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryQueryInfoAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => QueryInfoAsync(openHandle, informationClass, outputBufferLength, cancellationToken));
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
        /// Enumerate an existing directory open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="informationClass">Requested directory-information class.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="flags">Query-directory flags.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryQueryDirectoryAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength = DefaultQueryBufferLength,
            string? fileNamePattern = null,
            Smb2QueryDirectoryFlags flags = Smb2QueryDirectoryFlags.RestartScans,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => QueryDirectoryAsync(
                openHandle,
                informationClass,
                outputBufferLength,
                fileNamePattern,
                flags,
                cancellationToken));
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
        /// Wait for a bounded SMB2 CHANGE_NOTIFY completion and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked directory open handle.</param>
        /// <param name="completionFilter">Requested completion filter.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the open directory.</param>
        /// <param name="outputBufferLength">Requested output buffer length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<FileNotifyInformation[]>> TryChangeNotifyAsync(
            OpenCifsClientOpenHandle openHandle,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            uint outputBufferLength = DefaultChangeNotifyBufferLength,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ChangeNotifyAsync(
                openHandle,
                completionFilter,
                watchTree,
                outputBufferLength,
                cancellationToken));
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
        /// Apply a FILE_BASIC_INFORMATION mutation and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="information">Basic-information payload.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetBasicInfoAsync(OpenCifsClientOpenHandle openHandle, FileBasicInformation information, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetBasicInfoAsync(openHandle, information, cancellationToken));
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
        /// Apply a FILE_END_OF_FILE_INFORMATION mutation and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetEndOfFileAsync(OpenCifsClientOpenHandle openHandle, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetEndOfFileAsync(openHandle, endOfFile, cancellationToken));
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
        /// Apply a FILE_ALLOCATION_INFORMATION mutation and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="allocationSize">Requested allocation size.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetAllocationSizeAsync(OpenCifsClientOpenHandle openHandle, ulong allocationSize, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetAllocationSizeAsync(openHandle, allocationSize, cancellationToken));
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
        /// Apply FILE_DISPOSITION_INFORMATION and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="deletePending">Delete-pending state.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetDeletePendingAsync(OpenCifsClientOpenHandle openHandle, bool deletePending = true, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetDeletePendingAsync(openHandle, deletePending, cancellationToken));
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
        /// Apply FILE_RENAME_INFORMATION and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="path">New relative path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetRenameAsync(
            OpenCifsClientOpenHandle openHandle,
            string path,
            bool replaceIfExists = false,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetRenameAsync(openHandle, path, replaceIfExists, cancellationToken));
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
        /// Close an existing file or directory open and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="openHandle">Tracked open handle.</param>
        /// <param name="postQueryAttributes">Whether to request post-close attributes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<Smb2CloseResponse>> TryCloseAsync(
            OpenCifsClientOpenHandle openHandle,
            bool postQueryAttributes = false,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CloseAsync(openHandle, postQueryAttributes, cancellationToken));
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

        /// <summary>
        /// Disconnect all active trees, log off the session, and preserve typed client failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryDisconnectAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => DisconnectAsync(cancellationToken));
        }

        internal async Task SimulateTransportDisconnectAsync()
        {
            ThrowIfDisposed();

            if (_Connection == null)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
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
            byte[] requestBody = request.ToByteArray();
            _Session.AppendPreauthMessageBytes(requestHeader, requestBody);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, requestBody, cancellationToken).ConfigureAwait(false);

            if (responseHeader.Status != NtStatus.Success)
            {
                throw OpenCifsStatusException.CreateFromResponsePayload(
                    Smb2Command.Negotiate,
                    responseHeader.Status,
                    responsePayload);
            }

            _Session.AppendPreauthMessageBytes(responseHeader, responsePayload);
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
            Smb2CreateRequest? originatingRequest,
            bool isDirectory,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel)
        {
            OpenState openState = _Session.ApplyCreateResult(treeHandle.TreeId, path, responseHeader.Status, createResponse, originatingRequest);
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
                openState.UsesDurableHandleV2,
                openState.DurableCreateGuid,
                openState.DurableTimeoutMs,
                openState.IsPersistent,
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

        private async Task<Smb2CompoundPacket> SendCompoundRequestAsync(Smb2CompoundPacket requestPacket, CancellationToken cancellationToken)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            if (_Connection == null)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(requestPacket), cancellationToken).ConfigureAwait(false);
            byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            _Session.ValidateResponsePacket(responsePacket, responseBytes);
            _Session.ApplyCompoundResponsePacket(responsePacket);
            return responsePacket;
        }

        private async Task EnsureCreditsAsync(ushort requiredCredits, CancellationToken cancellationToken)
        {
            while (_Session.AvailableCredits < requiredCredits)
            {
                int previousCredits = _Session.AvailableCredits;
                await RequestCreditWindowGrowthAsync(requiredCredits, cancellationToken).ConfigureAwait(false);

                if (_Session.AvailableCredits <= previousCredits)
                {
                    throw new OpenCifsClientStateException("The SMB2 credit window could not be expanded enough for the requested operation.");
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
                throw new OpenCifsClientStateException("The client connection is not connected.");
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
                    responseBytes = await ReadNextResponsePacketBytesAsync(cancellationRequested ? CancellationToken.None : cancellationToken).ConfigureAwait(false);
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
                    throw new OpenCifsClientProtocolException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new OpenCifsClientProtocolException("The server response command does not match the request command.");
                }

                _Session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new OpenCifsClientProtocolException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
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
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(requestHeader, requestPayload)
            });

            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(requestPacket), cancellationToken).ConfigureAwait(false);

            while (true)
            {
                byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                if (requestHeader.Command != Smb2Command.SessionSetup)
                {
                    _Session.ValidateResponsePacket(responsePacket, responseBytes);
                }

                if (responsePacket.Entries.Count != 1)
                {
                    throw new OpenCifsClientProtocolException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new OpenCifsClientProtocolException("The server response command does not match the request command.");
                }

                _Session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new OpenCifsClientProtocolException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
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

        private async Task ValidateSecureNegotiateCoreAsync(uint treeId, CancellationToken cancellationToken)
        {
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: _Session.SessionId!.Value);
            Smb2IoctlRequest request = _Session.CreateValidateNegotiateInfoRequest(maxOutputResponse: 256);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            _Session.ApplyValidateNegotiateInfoResult(
                responseHeader.Status,
                ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2IoctlResponse.ReadFrom));
        }

        private async Task BindSrvsvcAsync(OpenCifsClientOpenHandle pipeHandle, CancellationToken cancellationToken)
        {
            DceRpcBindRequest bindRequest = new DceRpcBindRequest
            {
                CallId = GetNextRpcCallId()
            };
            byte[] bindResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                bindRequest.ToByteArray(),
                maxOutputResponse: 8192,
                cancellationToken).ConfigureAwait(false);
            DceRpcBindAck bindAck = DceRpcBindAck.ReadFrom(bindResponseBytes);
            bindAck.EnsureAccepted();
        }

        private async Task<OpenCifsRemoteShareInfo[]> EnumerateSrvsvcSharesAsync(OpenCifsClientOpenHandle pipeHandle, CancellationToken cancellationToken)
        {
            SrvsvcNetrShareEnumRequest request = new SrvsvcNetrShareEnumRequest();
            DceRpcRequestPdu rpcRequest = new DceRpcRequestPdu
            {
                CallId = GetNextRpcCallId(),
                ContextId = DceRpcConstants.SrvsvcContextId,
                OperationNumber = SrvsvcNetrShareEnumRequest.OperationNumber,
                StubData = request.ToByteArray()
            };

            byte[] rpcResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                rpcRequest.ToByteArray(),
                maxOutputResponse: DefaultPipeTransceiveOutputLength,
                cancellationToken).ConfigureAwait(false);
            DceRpcResponsePdu rpcResponse = DceRpcResponsePdu.ReadFrom(rpcResponseBytes);
            SrvsvcNetrShareEnumResponse shareResponse = SrvsvcNetrShareEnumResponse.ReadFrom(rpcResponse.StubData);
            OpenCifsRemoteShareInfo[] shares = new OpenCifsRemoteShareInfo[shareResponse.Shares.Length];

            for (int index = 0; index < shareResponse.Shares.Length; index++)
            {
                SrvsvcShareInfo1 share = shareResponse.Shares[index];
                shares[index] = new OpenCifsRemoteShareInfo
                {
                    Name = share.Name,
                    RawType = share.Type,
                    Remark = share.Remark
                };
            }

            return shares;
        }

        private async Task<OpenCifsRemoteShareInfo> GetSrvsvcShareInfoAsync(OpenCifsClientOpenHandle pipeHandle, string shareName, CancellationToken cancellationToken)
        {
            SrvsvcNetrShareGetInfoRequest request = new SrvsvcNetrShareGetInfoRequest
            {
                ShareName = shareName
            };
            DceRpcRequestPdu rpcRequest = new DceRpcRequestPdu
            {
                CallId = GetNextRpcCallId(),
                ContextId = DceRpcConstants.SrvsvcContextId,
                OperationNumber = SrvsvcNetrShareGetInfoRequest.OperationNumber,
                StubData = request.ToByteArray()
            };

            byte[] rpcResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                rpcRequest.ToByteArray(),
                maxOutputResponse: DefaultPipeTransceiveOutputLength,
                cancellationToken).ConfigureAwait(false);
            DceRpcResponsePdu rpcResponse = DceRpcResponsePdu.ReadFrom(rpcResponseBytes);
            SrvsvcNetrShareGetInfoResponse shareResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(rpcResponse.StubData);

            if (shareResponse.ReturnCode != SrvsvcNetrShareGetInfoResponse.ErrorSuccess)
            {
                throw new OpenCifsClientRpcException("SRVSVC", "NetrShareGetInfo", shareResponse.ReturnCode);
            }

            SrvsvcShareInfo2 share = shareResponse.Share ?? throw new OpenCifsClientProtocolException("The server SRVSVC share-info response omitted the required share details.");
            return new OpenCifsRemoteShareInfo
            {
                Name = share.Name,
                RawType = share.Type,
                Remark = share.Remark,
                Permissions = share.Permissions,
                MaximumUses = share.MaximumUses,
                CurrentUses = share.CurrentUses,
                LocalPath = share.Path
            };
        }

        private OpenCifsDfsReferral[] ConvertDfsReferralResponse(string requestedPath, DfsReferralResponse response)
        {
            if (response.Entries.Length == 0)
            {
                throw new OpenCifsClientProtocolException("The server DFS referral response did not contain any referral entries.");
            }

            OpenCifsDfsReferral[] referrals = new OpenCifsDfsReferral[response.Entries.Length];
            string fallbackReferralPath = DeriveReferralPathFromConsumed(requestedPath, response.PathConsumed);

            for (int index = 0; index < response.Entries.Length; index++)
            {
                DfsReferralEntryV2 entry = response.Entries[index];
                ParseDfsNetworkAddress(entry.NetworkAddress, out string targetServerName, out string targetShareName, out string targetPath);
                DateTime expiresAtUtc = DateTime.UtcNow.AddSeconds(entry.TimeToLive);
                string referralPath = string.IsNullOrWhiteSpace(entry.DfsPath)
                    ? fallbackReferralPath
                    : NormalizeDfsPath(entry.DfsPath);
                referrals[index] = new OpenCifsDfsReferral
                {
                    RequestedPath = requestedPath,
                    ReferralPath = referralPath,
                    NetworkAddress = entry.NetworkAddress,
                    TargetServerName = targetServerName,
                    TargetShareName = targetShareName,
                    TargetPath = targetPath,
                    PathConsumed = response.PathConsumed,
                    TimeToLiveSeconds = entry.TimeToLive,
                    ExpiresAtUtc = expiresAtUtc,
                    IsRootTarget = entry.IsRootTarget
                };
            }

            return referrals;
        }

        private OpenCifsResolvedDfsPath CreateResolvedDfsPath(string originalPath, OpenCifsDfsReferral[] referrals, bool wasResolvedFromCache)
        {
            if (referrals == null || referrals.Length == 0)
            {
                throw new OpenCifsClientProtocolException("At least one DFS referral entry is required to resolve a DFS path.");
            }

            OpenCifsDfsReferral referral = SelectPreferredDfsReferral(referrals);

            if ((referral.PathConsumed & 1) != 0)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count is not a valid Unicode byte count.");
            }

            int consumedCharacterCount = referral.PathConsumed / 2;

            if (consumedCharacterCount < 0 || consumedCharacterCount > originalPath.Length)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count exceeds the original DFS request path.");
            }

            string unresolvedSuffix = originalPath.Substring(consumedCharacterCount).Trim('\\');
            string targetRelativePath = CombineDfsRelativePath(referral.TargetPath, unresolvedSuffix);
            string targetUncPath = BuildTargetUncPath(referral.TargetServerName, referral.TargetShareName, targetRelativePath);
            return new OpenCifsResolvedDfsPath
            {
                OriginalPath = originalPath,
                ReferralPath = referral.ReferralPath,
                TargetServerName = referral.TargetServerName,
                TargetShareName = referral.TargetShareName,
                TargetRelativePath = targetRelativePath,
                TargetUncPath = targetUncPath,
                ExpiresAtUtc = referral.ExpiresAtUtc,
                WasResolvedFromCache = wasResolvedFromCache,
                IsSameServer = StringComparer.OrdinalIgnoreCase.Equals(NormalizeServerName(referral.TargetServerName), NormalizeServerName(Options.ServerName))
            };
        }

        private bool TryResolveDfsPathFromCache(string normalizedDfsPath, out OpenCifsResolvedDfsPath? resolvedPath)
        {
            PruneExpiredDfsReferralCache();
            resolvedPath = null;
            DfsReferralCacheEntry? bestEntry = null;
            int bestMatchLength = -1;

            foreach (DfsReferralCacheEntry cacheEntry in _DfsReferralCache.Values)
            {
                if (!DoesDfsPrefixMatch(cacheEntry.ReferralPath, normalizedDfsPath))
                {
                    continue;
                }

                if (cacheEntry.ReferralPath.Length > bestMatchLength)
                {
                    bestMatchLength = cacheEntry.ReferralPath.Length;
                    bestEntry = cacheEntry;
                }
            }

            if (bestEntry == null)
            {
                return false;
            }

            resolvedPath = CreateResolvedDfsPath(normalizedDfsPath, bestEntry.Referrals, wasResolvedFromCache: true);
            return true;
        }

        private void UpdateDfsReferralCache(OpenCifsDfsReferral[] referrals)
        {
            if (referrals == null || referrals.Length == 0)
            {
                return;
            }

            string referralPath = NormalizeDfsPath(referrals[0].ReferralPath);
            DateTime expiresAtUtc = referrals[0].ExpiresAtUtc;

            for (int index = 1; index < referrals.Length; index++)
            {
                if (referrals[index].ExpiresAtUtc < expiresAtUtc)
                {
                    expiresAtUtc = referrals[index].ExpiresAtUtc;
                }
            }

            _DfsReferralCache[referralPath] = new DfsReferralCacheEntry
            {
                ReferralPath = referralPath,
                ExpiresAtUtc = expiresAtUtc,
                Referrals = CloneDfsReferrals(referrals)
            };
        }

        private void PruneExpiredDfsReferralCache()
        {
            DateTime utcNow = DateTime.UtcNow;
            List<string>? expiredKeys = null;

            foreach (KeyValuePair<string, DfsReferralCacheEntry> cacheEntry in _DfsReferralCache)
            {
                if (cacheEntry.Value.ExpiresAtUtc > utcNow)
                {
                    continue;
                }

                expiredKeys ??= new List<string>();
                expiredKeys.Add(cacheEntry.Key);
            }

            if (expiredKeys == null)
            {
                return;
            }

            for (int index = 0; index < expiredKeys.Count; index++)
            {
                _DfsReferralCache.Remove(expiredKeys[index]);
            }
        }

        private async Task<byte[]> PipeTransceiveAsync(
            OpenCifsClientOpenHandle pipeHandle,
            byte[] inputBuffer,
            uint maxOutputResponse,
            CancellationToken cancellationToken)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer), "InputBuffer cannot be null.");
            }

            ValidateOpenHandle(pipeHandle);
            Smb2IoctlRequest request = _Session.CreateIoctlRequest(
                pipeHandle.PersistentFileId,
                pipeHandle.VolatileFileId,
                (uint)FsctlCode.PipeTransceive,
                inputBuffer,
                maxOutputResponse: maxOutputResponse,
                maxInputResponse: 0,
                flags: Smb2IoctlFlags.IsFsctl);
            Smb2Header requestHeader = _Session.CreateRequestHeader(Smb2Command.Ioctl, pipeHandle.TreeId, sessionId: _Session.SessionId!.Value);
            (Smb2Header responseHeader, byte[] responsePayload) = await SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);

            if (responseHeader.Status != NtStatus.Success &&
                responseHeader.Status != NtStatus.BufferOverflow)
            {
                throw OpenCifsStatusException.CreateFromResponsePayload(Smb2Command.Ioctl, responseHeader.Status, responsePayload);
            }

            Smb2IoctlResponse response = Smb2IoctlResponse.ReadFrom(responsePayload);

            if (response.CtlCode != (uint)FsctlCode.PipeTransceive)
            {
                throw new OpenCifsClientProtocolException("The server IOCTL response does not contain an FSCTL_PIPE_TRANSCEIVE payload.");
            }

            if (response.PersistentFileId != pipeHandle.PersistentFileId ||
                response.VolatileFileId != pipeHandle.VolatileFileId)
            {
                throw new OpenCifsClientProtocolException("The server IOCTL response file identifier does not match the named-pipe open handle.");
            }

            return response.OutputBuffer;
        }

        private static string NormalizePipeName(string pipeName)
        {
            if (string.IsNullOrWhiteSpace(pipeName))
            {
                throw new ArgumentNullException(nameof(pipeName), "PipeName cannot be null or whitespace.");
            }

            string normalizedPipeName = pipeName.Trim().Replace('/', '\\');

            while (normalizedPipeName.StartsWith("\\", StringComparison.Ordinal))
            {
                normalizedPipeName = normalizedPipeName.Substring(1);
            }

            if (normalizedPipeName.StartsWith("pipe\\", StringComparison.OrdinalIgnoreCase))
            {
                normalizedPipeName = normalizedPipeName.Substring("pipe\\".Length);
            }

            normalizedPipeName = normalizedPipeName.Trim('\\');

            if (normalizedPipeName.Length == 0)
            {
                throw new ArgumentException("PipeName cannot be empty after normalization.", nameof(pipeName));
            }

            return normalizedPipeName;
        }

        private async Task WriteCancelRequestAsync(ulong pendingMessageId)
        {
            if (_Connection == null)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            Smb2Header cancelHeader = _Session.CreateCancelRequestHeader(pendingMessageId);
            Smb2CancelRequest cancelRequest = _Session.CreateCancelRequest();
            Smb2CompoundPacket cancelPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(cancelHeader, cancelRequest.ToByteArray())
            });
            await _Connection.WriteAsync(_Session.FinalizeRequestPacket(cancelPacket), CancellationToken.None).ConfigureAwait(false);
        }

        private async Task<byte[]> ReadNextResponsePacketBytesAsync(CancellationToken cancellationToken)
        {
            if (_Connection == null)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            byte[] responseBytes = await _Connection.ReadAsync(cancellationToken).ConfigureAwait(false);
            return _Session.UnwrapResponsePacket(responseBytes);
        }

        private static void AssertCompoundResponseEntryCount(Smb2CompoundPacket responsePacket, int expectedCount)
        {
            if (responsePacket.Entries.Count != expectedCount)
            {
                throw new OpenCifsClientProtocolException(
                    "The managed direct-TCP client connection expected " +
                    expectedCount +
                    " SMB2 responses in the bounded compound-flow helper but received " +
                    responsePacket.Entries.Count +
                    '.');
            }
        }

        private static Smb2QueryInfoRequest CreateRelatedQueryInfoRequest(FileInformationClass informationClass, uint outputBufferLength)
        {
            Smb2QueryInfoRequest request = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                OutputBufferLength = outputBufferLength,
                AdditionalInformation = 0,
                Flags = 0,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                InputBuffer = Array.Empty<byte>()
            };
            Smb2QueryInfoRequestValidator.Validate(request);
            return request;
        }

        private static Smb2ReadRequest CreateRelatedReadRequest(uint length, ulong offset, uint minimumCount)
        {
            Smb2ReadRequest request = new Smb2ReadRequest
            {
                Length = length,
                Offset = offset,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                MinimumCount = minimumCount,
                Channel = 0,
                RemainingBytes = 0,
                ReadChannelInfo = Array.Empty<byte>()
            };
            Smb2ReadRequestValidator.Validate(request);
            return request;
        }

        private static Smb2WriteRequest CreateRelatedWriteRequest(byte[] data, ulong offset)
        {
            Smb2WriteRequest request = new Smb2WriteRequest
            {
                Offset = offset,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                Flags = Smb2WriteFlags.None,
                Channel = 0,
                RemainingBytes = 0,
                WriteChannelInfo = Array.Empty<byte>(),
                DataBuffer = (byte[])data.Clone()
            };
            Smb2WriteRequestValidator.Validate(request);
            return request;
        }

        private static Smb2FlushRequest CreateRelatedFlushRequest()
        {
            Smb2FlushRequest request = new Smb2FlushRequest
            {
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId
            };
            Smb2FlushRequestValidator.Validate(request);
            return request;
        }

        private static Smb2CloseRequest CreateRelatedCloseRequest()
        {
            Smb2CloseRequest request = new Smb2CloseRequest
            {
                Flags = Smb2CloseFlags.None,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId
            };
            Smb2CloseRequestValidator.Validate(request);
            return request;
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
                throw new OpenCifsClientStateException(
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
                throw new OpenCifsClientStateException("The unsolicited SMB2 oplock-break notification does not match a tracked client open handle.");
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
                throw new OpenCifsClientStateException("A negotiated direct-TCP connection is required before authenticating.");
            }
        }

        private void EnsureAuthenticatedSession()
        {
            ThrowIfDisposed();

            if (_Connection == null || !_Session.IsAuthenticated || _Session.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated direct-TCP session is required before issuing low-level client operations.");
            }
        }

        private bool ShouldValidateSecureNegotiate()
        {
            return _Session.NegotiatedDialect.HasValue &&
                _Session.NegotiatedDialect.Value >= SmbDialect.Smb30;
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
                throw new OpenCifsClientStateException("The specified tree handle does not belong to the current client connection lifecycle.");
            }

            if (treeHandle.IsDisconnected)
            {
                throw new OpenCifsClientStateException("The specified tree handle has already been disconnected.");
            }

            if (!_ActiveTreesById.TryGetValue(treeHandle.TreeId, out OpenCifsClientTreeHandle? trackedTreeHandle) || !ReferenceEquals(trackedTreeHandle, treeHandle))
            {
                throw new OpenCifsClientStateException("The specified tree handle is no longer active on this client connection.");
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
                throw new OpenCifsClientStateException("The specified open handle does not belong to the current client connection lifecycle.");
            }

            if (openHandle.IsClosed)
            {
                throw new OpenCifsClientStateException("The specified open handle has already been closed.");
            }

            ValidateTreeHandle(openHandle.TreeHandle);
            string key = GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId);

            if (!_ActiveOpensByKey.TryGetValue(key, out OpenCifsClientOpenHandle? trackedOpenHandle) || !ReferenceEquals(trackedOpenHandle, openHandle))
            {
                throw new OpenCifsClientStateException("The specified open handle is no longer active on this client connection.");
            }
        }

        private void ValidateFileOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (openHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException(operationName + " requires a file open.");
            }
        }

        private void ValidateDirectoryOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (!openHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException(operationName + " requires a directory open.");
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
                throw new OpenCifsClientStateException("The client connection has been disposed.");
            }
        }

        private void ResetSession(bool invalidateDurableReconnect = true)
        {
            Guid clientGuid = _Session.ClientGuid;
            InvalidateTrackedHandles(invalidateDurableReconnect);
            _DfsReferralCache.Clear();
            _SessionGeneration++;
            _Session = new OpenCifsClientSession(Options, clientGuid);
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

        private static string NormalizeDfsPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\');

            while (normalizedPath.StartsWith("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Substring(1);
            }

            normalizedPath = "\\" + normalizedPath.Trim('\\');

            while (normalizedPath.Contains("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Replace("\\\\", "\\", StringComparison.Ordinal);
            }

            return normalizedPath;
        }

        private static string DeriveReferralPathFromConsumed(string requestedPath, ushort pathConsumed)
        {
            if ((pathConsumed & 1) != 0)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count is not a valid Unicode byte count.");
            }

            int consumedCharacterCount = pathConsumed / 2;

            if (consumedCharacterCount < 0 || consumedCharacterCount > requestedPath.Length)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count exceeds the original DFS request path.");
            }

            return NormalizeDfsPath(requestedPath.Substring(0, consumedCharacterCount));
        }

        private static bool DoesDfsPrefixMatch(string referralPath, string requestedPath)
        {
            if (string.Equals(referralPath, requestedPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return requestedPath.StartsWith(referralPath + "\\", StringComparison.OrdinalIgnoreCase);
        }

        private static OpenCifsDfsReferral SelectPreferredDfsReferral(OpenCifsDfsReferral[] referrals)
        {
            for (int index = 0; index < referrals.Length; index++)
            {
                if (!referrals[index].IsRootTarget)
                {
                    return referrals[index];
                }
            }

            return referrals[0];
        }

        private static void ParseDfsNetworkAddress(string networkAddress, out string serverName, out string shareName, out string targetPath)
        {
            string normalizedNetworkAddress = NormalizeDfsPath(networkAddress);
            string[] parts = normalizedNetworkAddress.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                throw new OpenCifsClientProtocolException("The DFS referral target network address is malformed.");
            }

            serverName = parts[0];
            shareName = parts[1];
            targetPath = parts.Length <= 2 ? string.Empty : string.Join("\\", parts, 2, parts.Length - 2);
        }

        private static string CombineDfsRelativePath(string basePath, string suffix)
        {
            string normalizedBasePath = string.IsNullOrWhiteSpace(basePath) ? string.Empty : basePath.Replace('/', '\\').Trim('\\');
            string normalizedSuffix = string.IsNullOrWhiteSpace(suffix) ? string.Empty : suffix.Replace('/', '\\').Trim('\\');

            if (normalizedBasePath.Length == 0)
            {
                return normalizedSuffix;
            }

            if (normalizedSuffix.Length == 0)
            {
                return normalizedBasePath;
            }

            return normalizedBasePath + "\\" + normalizedSuffix;
        }

        private static string BuildTargetUncPath(string serverName, string shareName, string targetPath)
        {
            string normalizedServerName = NormalizeServerName(serverName);
            string normalizedShareName = shareName.Trim().Trim('\\');
            string normalizedTargetPath = string.IsNullOrWhiteSpace(targetPath) ? string.Empty : targetPath.Replace('/', '\\').Trim('\\');
            return normalizedTargetPath.Length == 0
                ? "\\\\" + normalizedServerName + "\\" + normalizedShareName
                : "\\\\" + normalizedServerName + "\\" + normalizedShareName + "\\" + normalizedTargetPath;
        }

        private static string NormalizeServerName(string serverName)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                return string.Empty;
            }

            return serverName.Trim().Trim('\\');
        }

        private static OpenCifsDfsReferral[] CloneDfsReferrals(OpenCifsDfsReferral[] referrals)
        {
            OpenCifsDfsReferral[] clones = new OpenCifsDfsReferral[referrals.Length];

            for (int index = 0; index < referrals.Length; index++)
            {
                OpenCifsDfsReferral referral = referrals[index];
                clones[index] = new OpenCifsDfsReferral
                {
                    RequestedPath = referral.RequestedPath,
                    ReferralPath = referral.ReferralPath,
                    NetworkAddress = referral.NetworkAddress,
                    TargetServerName = referral.TargetServerName,
                    TargetShareName = referral.TargetShareName,
                    TargetPath = referral.TargetPath,
                    PathConsumed = referral.PathConsumed,
                    TimeToLiveSeconds = referral.TimeToLiveSeconds,
                    ExpiresAtUtc = referral.ExpiresAtUtc,
                    IsRootTarget = referral.IsRootTarget
                };
            }

            return clones;
        }

        private uint GetNextRpcCallId()
        {
            lock (_RpcSyncRoot)
            {
                uint callId = _NextRpcCallId++;
                if (_NextRpcCallId == 0)
                {
                    _NextRpcCallId = 1;
                }

                return callId;
            }
        }

        private readonly Dictionary<uint, OpenCifsClientTreeHandle> _ActiveTreesById = new Dictionary<uint, OpenCifsClientTreeHandle>();
        private readonly Dictionary<string, OpenCifsClientOpenHandle> _ActiveOpensByKey = new Dictionary<string, OpenCifsClientOpenHandle>(StringComparer.Ordinal);
        private readonly Dictionary<string, DfsReferralCacheEntry> _DfsReferralCache = new Dictionary<string, DfsReferralCacheEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Guid _ConnectionId = Guid.NewGuid();
        private readonly object _RpcSyncRoot = new object();
        private OpenCifsClientSession _Session;
        private FramedPipeConnection? _Connection;
        private TcpClient? _TcpClient;
        private uint _NextRpcCallId = 1;
        private long _SessionGeneration;
        private bool _Disposed;
        private bool _AsyncDisposed;

        private sealed class DfsReferralCacheEntry
        {
            public string ReferralPath { get; set; } = string.Empty;

            public DateTime ExpiresAtUtc { get; set; }

            public OpenCifsDfsReferral[] Referrals { get; set; } = Array.Empty<OpenCifsDfsReferral>();
        }
    }
}


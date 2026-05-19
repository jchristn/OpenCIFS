namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Transport;

    internal sealed class OpenCifsClientConnectionLifecycleService
    {
        public OpenCifsClientConnectionLifecycleService(
            OpenCifsClientOptions options,
            Action throwIfDisposed,
            Func<FramedPipeConnection?> getConnection,
            Action<TcpClient?> setTcpClient,
            Action<FramedPipeConnection?> setConnection,
            Action resetSession,
            Func<Task> resetTransportAsync,
            Func<OpenCifsClientSession> getSession,
            Action ensureNegotiatedConnection,
            Action ensureAuthenticatedSession,
            Func<IReadOnlyCollection<OpenCifsClientTreeHandle>> getActiveTrees,
            Action<OpenCifsClientTreeHandle> markTreeDisconnected,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> sendSingleRequestAsync)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _ThrowIfDisposed = throwIfDisposed ?? throw new ArgumentNullException(nameof(throwIfDisposed), "ThrowIfDisposed cannot be null.");
            _GetConnection = getConnection ?? throw new ArgumentNullException(nameof(getConnection), "GetConnection cannot be null.");
            _SetTcpClient = setTcpClient ?? throw new ArgumentNullException(nameof(setTcpClient), "SetTcpClient cannot be null.");
            _SetConnection = setConnection ?? throw new ArgumentNullException(nameof(setConnection), "SetConnection cannot be null.");
            _ResetSession = resetSession ?? throw new ArgumentNullException(nameof(resetSession), "ResetSession cannot be null.");
            _ResetTransportAsync = resetTransportAsync ?? throw new ArgumentNullException(nameof(resetTransportAsync), "ResetTransportAsync cannot be null.");
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _EnsureNegotiatedConnection = ensureNegotiatedConnection ?? throw new ArgumentNullException(nameof(ensureNegotiatedConnection), "EnsureNegotiatedConnection cannot be null.");
            _EnsureAuthenticatedSession = ensureAuthenticatedSession ?? throw new ArgumentNullException(nameof(ensureAuthenticatedSession), "EnsureAuthenticatedSession cannot be null.");
            _GetActiveTrees = getActiveTrees ?? throw new ArgumentNullException(nameof(getActiveTrees), "GetActiveTrees cannot be null.");
            _MarkTreeDisconnected = markTreeDisconnected ?? throw new ArgumentNullException(nameof(markTreeDisconnected), "MarkTreeDisconnected cannot be null.");
            _SendSingleRequestAsync = sendSingleRequestAsync ?? throw new ArgumentNullException(nameof(sendSingleRequestAsync), "SendSingleRequestAsync cannot be null.");
        }

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            _ThrowIfDisposed();

            if (_GetConnection() != null)
            {
                throw new OpenCifsClientStateException("The client connection is already connected.");
            }

            _ResetSession();

            using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(_Options.ConnectTimeoutMs);
            using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
            CancellationToken linkedToken = linkedTokenSource.Token;

            try
            {
                TcpClient tcpClient = new TcpClient();
                _SetTcpClient(tcpClient);
                await tcpClient.ConnectAsync(_Options.ServerName, _Options.ServerPort, linkedToken).ConfigureAwait(false);
                NetworkStream networkStream = tcpClient.GetStream();
                FramedPipeConnection connection = FramedPipeConnection.Create(networkStream, new DirectTcpFrameProtocol());
                _SetConnection(connection);
                connection.Start();
                await NegotiateAsync(linkedToken).ConfigureAwait(false);
            }
            catch
            {
                await _ResetTransportAsync().ConfigureAwait(false);
                _ResetSession();
                throw;
            }
        }

        public async Task AuthenticateAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken)
        {
            _ThrowIfDisposed();

            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential), "Credential cannot be null.");
            }

            _EnsureNegotiatedConnection();

            if (_GetSession().IsAuthenticated)
            {
                throw new OpenCifsClientStateException("The client connection is already authenticated.");
            }

            try
            {
                OpenCifsClientSession session = _GetSession();
                Smb2Header challengeHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                Smb2SessionSetupRequest initialRequest = session.CreateSessionSetupRequest(credential);
                byte[] initialRequestBody = initialRequest.ToByteArray();
                session.AppendPreauthMessageBytes(challengeHeader, initialRequestBody);
                OpenCifsClientRequestResponse challengeResponseEnvelope = await _SendSingleRequestAsync(
                    challengeHeader,
                    initialRequestBody,
                    cancellationToken).ConfigureAwait(false);
                Smb2Header challengeResponseHeader = challengeResponseEnvelope.ResponseHeader;
                byte[] challengeResponsePayload = challengeResponseEnvelope.ResponsePayload;

                if (challengeResponseHeader.Status != NtStatus.MoreProcessingRequired)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(
                        Smb2Command.SessionSetup,
                        challengeResponseHeader.Status,
                        challengeResponsePayload);
                }

                session.AppendPreauthMessageBytes(challengeResponseHeader, challengeResponsePayload);
                Smb2SessionSetupResponse challengeResponse = Smb2SessionSetupResponse.ReadFrom(challengeResponsePayload);
                Smb2SessionSetupRequest authenticateRequest = session.CreateSessionAuthenticateRequest(
                    credential,
                    challengeResponseHeader.SessionId,
                    challengeResponseHeader.Status,
                    challengeResponse);
                Smb2Header authenticateHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResponseHeader.SessionId);
                byte[] authenticateRequestBody = authenticateRequest.ToByteArray();
                session.AppendPreauthMessageBytes(authenticateHeader, authenticateRequestBody);
                OpenCifsClientRequestResponse authenticateResponseEnvelope = await _SendSingleRequestAsync(
                    authenticateHeader,
                    authenticateRequestBody,
                    cancellationToken).ConfigureAwait(false);
                Smb2Header authenticateResponseHeader = authenticateResponseEnvelope.ResponseHeader;
                byte[] authenticateResponsePayload = authenticateResponseEnvelope.ResponsePayload;

                if (authenticateResponseHeader.Status != NtStatus.Success)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(
                        Smb2Command.SessionSetup,
                        authenticateResponseHeader.Status,
                        authenticateResponsePayload);
                }

                session.ApplySessionSetupResult(
                    authenticateResponseHeader.SessionId,
                    authenticateResponseHeader.Status,
                    Smb2SessionSetupResponse.ReadFrom(authenticateResponsePayload));
            }
            catch
            {
                await _ResetTransportAsync().ConfigureAwait(false);
                _ResetSession();
                throw;
            }
        }

        public async Task EchoAsync(CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientSession session = _GetSession();
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Echo, sessionId: session.SessionId!.Value);
            Smb2EchoRequest request = session.CreateEchoRequest();
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            session.ApplyEchoResult(
                responseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2EchoResponse.ReadFrom));
        }

        public async Task<int> RequestMaximumCreditsAsync(CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientSession session = _GetSession();
            int previousCredits = -1;

            while (session.AvailableCredits > previousCredits)
            {
                previousCredits = session.AvailableCredits;
                await RequestCreditWindowGrowthAsync(UInt16.MaxValue, cancellationToken).ConfigureAwait(false);
                session = _GetSession();
            }

            return session.AvailableCredits;
        }

        public async Task EnsureCreditsAsync(ushort requiredCredits, CancellationToken cancellationToken)
        {
            OpenCifsClientSession session = _GetSession();

            while (session.AvailableCredits < requiredCredits)
            {
                int previousCredits = session.AvailableCredits;
                await RequestCreditWindowGrowthAsync(requiredCredits, cancellationToken).ConfigureAwait(false);
                session = _GetSession();

                if (session.AvailableCredits <= previousCredits)
                {
                    throw new OpenCifsClientStateException("The SMB2 credit window could not be expanded enough for the requested operation.");
                }
            }
        }

        public async Task DisconnectCoreAsync(CancellationToken cancellationToken)
        {
            _ThrowIfDisposed();

            if (_GetConnection() == null)
            {
                _ResetSession();
                return;
            }

            try
            {
                OpenCifsClientSession session = _GetSession();
                List<OpenCifsClientTreeHandle> connectedTrees = new List<OpenCifsClientTreeHandle>(_GetActiveTrees());

                for (int index = 0; index < connectedTrees.Count; index++)
                {
                    OpenCifsClientTreeHandle treeHandle = connectedTrees[index];

                    if (treeHandle.IsDisconnected)
                    {
                        continue;
                    }

                    Smb2TreeDisconnectRequest treeDisconnectRequest = session.CreateTreeDisconnectRequest(treeHandle.TreeId);
                    Smb2Header treeDisconnectHeader = session.CreateRequestHeader(Smb2Command.TreeDisconnect, treeHandle.TreeId, sessionId: session.SessionId!.Value);
                    OpenCifsClientRequestResponse treeDisconnectResponseEnvelope = await _SendSingleRequestAsync(
                        treeDisconnectHeader,
                        treeDisconnectRequest.ToByteArray(),
                        cancellationToken).ConfigureAwait(false);
                    Smb2Header treeDisconnectResponseHeader = treeDisconnectResponseEnvelope.ResponseHeader;
                    byte[] treeDisconnectResponsePayload = treeDisconnectResponseEnvelope.ResponsePayload;
                    session.ApplyTreeDisconnectResult(
                        treeHandle.TreeId,
                        treeDisconnectResponseHeader.Status,
                        Smb2TreeDisconnectResponse.ReadFrom(treeDisconnectResponsePayload));
                    _MarkTreeDisconnected(treeHandle);
                }

                if (session.IsAuthenticated)
                {
                    Smb2LogoffRequest logoffRequest = session.CreateLogoffRequest();
                    Smb2Header logoffHeader = session.CreateRequestHeader(Smb2Command.Logoff, sessionId: session.SessionId!.Value);
                    OpenCifsClientRequestResponse logoffResponseEnvelope = await _SendSingleRequestAsync(
                        logoffHeader,
                        logoffRequest.ToByteArray(),
                        cancellationToken).ConfigureAwait(false);
                    Smb2Header logoffResponseHeader = logoffResponseEnvelope.ResponseHeader;
                    byte[] logoffResponsePayload = logoffResponseEnvelope.ResponsePayload;
                    session.ApplyLogoffResult(
                        logoffResponseHeader.Status,
                        OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(logoffResponseHeader.Status, logoffResponsePayload, Smb2LogoffResponse.ReadFrom));
                }
            }
            finally
            {
                await _ResetTransportAsync().ConfigureAwait(false);
                _ResetSession();
            }
        }

        private async Task NegotiateAsync(CancellationToken cancellationToken)
        {
            OpenCifsClientSession session = _GetSession();
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Negotiate);
            Smb2NegotiateRequest request = session.CreateNegotiateRequest();
            byte[] requestBody = request.ToByteArray();
            session.AppendPreauthMessageBytes(requestHeader, requestBody);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, requestBody, cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;

            if (responseHeader.Status != NtStatus.Success)
            {
                throw OpenCifsStatusException.CreateFromResponsePayload(
                    Smb2Command.Negotiate,
                    responseHeader.Status,
                    responsePayload);
            }

            session.AppendPreauthMessageBytes(responseHeader, responsePayload);
            session.ApplyNegotiateResponse(Smb2NegotiateResponse.ReadFrom(responsePayload));
        }

        private async Task RequestCreditWindowGrowthAsync(ushort requestedCredits, CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientSession session = _GetSession();
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Echo, creditRequest: requestedCredits, sessionId: session.SessionId!.Value);
            Smb2EchoRequest request = session.CreateEchoRequest();
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            session.ApplyEchoResult(
                responseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2EchoResponse.ReadFrom));
        }

        private readonly OpenCifsClientOptions _Options;
        private readonly Action _ThrowIfDisposed;
        private readonly Func<FramedPipeConnection?> _GetConnection;
        private readonly Action<TcpClient?> _SetTcpClient;
        private readonly Action<FramedPipeConnection?> _SetConnection;
        private readonly Action _ResetSession;
        private readonly Func<Task> _ResetTransportAsync;
        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action _EnsureNegotiatedConnection;
        private readonly Action _EnsureAuthenticatedSession;
        private readonly Func<IReadOnlyCollection<OpenCifsClientTreeHandle>> _GetActiveTrees;
        private readonly Action<OpenCifsClientTreeHandle> _MarkTreeDisconnected;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> _SendSingleRequestAsync;
    }
}

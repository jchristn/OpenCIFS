namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Primary OpenCIFS client happy-path surface.
    /// </summary>
    public sealed class OpenCifsClient : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Initialize the primary OpenCIFS client surface.
        /// </summary>
        /// <param name="settings">Immutable validated client settings.</param>
        public OpenCifsClient(OpenCifsClientSettings settings)
        {
            Settings = settings ?? throw new ArgumentNullException(nameof(settings), "Settings cannot be null.");
            _Connection = new OpenCifsClientConnection(Settings.ToOptions());
        }

        /// <summary>
        /// Immutable validated client settings.
        /// </summary>
        public OpenCifsClientSettings Settings { get; }

        /// <summary>
        /// Whether a direct-TCP transport connection is currently active.
        /// </summary>
        public bool IsConnected
        {
            get
            {
                return _Connection.IsConnected;
            }
        }

        /// <summary>
        /// Whether the active client session is authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return _Connection.IsAuthenticated;
            }
        }

        /// <summary>
        /// Current low-level client session for the active or next connection lifecycle.
        /// </summary>
        public OpenCifsClientSession Session
        {
            get
            {
                return _Connection.Session;
            }
        }

        /// <summary>
        /// Advanced/raw direct-TCP connection surface for protocol-exact workflows.
        /// </summary>
        public OpenCifsClientConnection AdvancedConnection
        {
            get
            {
                return _Connection;
            }
        }

        /// <summary>
        /// Connect, negotiate, and authenticate against the configured direct-TCP endpoint.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public Task ConnectAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.ConnectAndAuthenticateAsync(credential, cancellationToken);
        }

        /// <summary>
        /// Connect, negotiate, and authenticate against the configured direct-TCP endpoint without throwing for typed client failures.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryConnectAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ConnectAsync(credential, cancellationToken));
        }

        /// <summary>
        /// Send an authenticated SMB2 echo request on the current session.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public Task EchoAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.EchoAsync(cancellationToken);
        }

        /// <summary>
        /// Send an authenticated SMB2 echo request on the current session without throwing for typed client failures.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryEchoAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => EchoAsync(cancellationToken));
        }

        /// <summary>
        /// Open a share-scoped primary work session.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Share-scoped primary work session.</returns>
        public async Task<OpenCifsShareSession> OpenShareAsync(string shareName, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            OpenCifsClientTreeHandle treeHandle = await _Connection.TreeConnectAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsShareSession shareSession = new OpenCifsShareSession(this, treeHandle);

            lock (_SyncRoot)
            {
                _OpenShareSessions.Add(shareSession);
            }

            return shareSession;
        }

        /// <summary>
        /// Open a share-scoped primary work session without throwing for typed client failures.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsShareSession>> TryOpenShareAsync(string shareName, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => OpenShareAsync(shareName, cancellationToken));
        }

        /// <summary>
        /// Enumerate remote shares through the OpenCIFS IPC$ / SRVSVC client path.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Remote share entries.</returns>
        public Task<OpenCifsRemoteShareInfo[]> EnumerateSharesAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.EnumerateRemoteSharesAsync(cancellationToken);
        }

        /// <summary>
        /// Enumerate remote shares without throwing for typed client failures.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsRemoteShareInfo[]>> TryEnumerateSharesAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => EnumerateSharesAsync(cancellationToken));
        }

        /// <summary>
        /// Query bounded detailed information for a single remote share through the OpenCIFS IPC$ / SRVSVC client path.
        /// </summary>
        /// <param name="shareName">Remote share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Detailed remote share information.</returns>
        public Task<OpenCifsRemoteShareInfo> GetShareInfoAsync(string shareName, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.GetRemoteShareInfoAsync(shareName, cancellationToken);
        }

        /// <summary>
        /// Query bounded detailed information for a single remote share without throwing for typed client failures.
        /// </summary>
        /// <param name="shareName">Remote share name.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsRemoteShareInfo>> TryGetShareInfoAsync(string shareName, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => GetShareInfoAsync(shareName, cancellationToken));
        }

        /// <summary>
        /// Query bounded DFS referrals through the OpenCIFS IPC$ / connection-scoped IOCTL path.
        /// </summary>
        /// <param name="dfsPath">DFS path such as <c>\server\share\link</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Returned DFS referral entries.</returns>
        public Task<OpenCifsDfsReferral[]> GetDfsReferralsAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.GetDfsReferralsAsync(dfsPath, cancellationToken);
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
        public Task<OpenCifsResolvedDfsPath> ResolveDfsPathAsync(string dfsPath, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.ResolveDfsPathAsync(dfsPath, cancellationToken);
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
        public Task<byte[]> TransceiveNamedPipeAsync(
            string pipeName,
            byte[] inputBuffer,
            uint maxOutputResponse = 65536,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return _Connection.TransceiveNamedPipeAsync(pipeName, inputBuffer, maxOutputResponse, cancellationToken);
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
            uint maxOutputResponse = 65536,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => TransceiveNamedPipeAsync(pipeName, inputBuffer, maxOutputResponse, cancellationToken));
        }

        /// <summary>
        /// Disconnect all open shares, log off the session, and close the underlying transport.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            await CloseTrackedShareSessionsAsync(cancellationToken).ConfigureAwait(false);
            await _Connection.DisconnectAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Disconnect all open shares, log off the session, and close the underlying transport without throwing for typed client failures.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryDisconnectAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => DisconnectAsync(cancellationToken));
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (_Disposed)
            {
                return;
            }

            CloseTrackedShareSessions();
            _Connection.Dispose();
            _Disposed = true;
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            if (_Disposed)
            {
                return;
            }

            await CloseTrackedShareSessionsAsync(CancellationToken.None).ConfigureAwait(false);
            await _Connection.DisposeAsync().ConfigureAwait(false);
            _Disposed = true;
            GC.SuppressFinalize(this);
        }

        internal OpenCifsClientConnection Connection
        {
            get
            {
                return _Connection;
            }
        }

        internal async Task CloseShareSessionAsync(OpenCifsShareSession shareSession, CancellationToken cancellationToken)
        {
            if (shareSession == null)
            {
                throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
            }

            bool removed;

            lock (_SyncRoot)
            {
                removed = _OpenShareSessions.Remove(shareSession);
            }

            shareSession.MarkClosed();

            if (!removed)
            {
                return;
            }

            if (!_Connection.IsConnected || !_Connection.IsAuthenticated || shareSession.TreeHandle.IsDisconnected)
            {
                return;
            }

            try
            {
                await _Connection.TreeDisconnectAsync(shareSession.TreeHandle, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void CloseTrackedShareSessions()
        {
            OpenCifsShareSession[] shareSessions = DrainTrackedShareSessions();

            for (int index = 0; index < shareSessions.Length; index++)
            {
                shareSessions[index].MarkClosed();
            }
        }

        private async Task CloseTrackedShareSessionsAsync(CancellationToken cancellationToken)
        {
            OpenCifsShareSession[] shareSessions = DrainTrackedShareSessions();

            for (int index = 0; index < shareSessions.Length; index++)
            {
                OpenCifsShareSession shareSession = shareSessions[index];
                shareSession.MarkClosed();

                if (!_Connection.IsConnected || !_Connection.IsAuthenticated || shareSession.TreeHandle.IsDisconnected)
                {
                    continue;
                }

                try
                {
                    await _Connection.TreeDisconnectAsync(shareSession.TreeHandle, cancellationToken).ConfigureAwait(false);
                }
                catch (InvalidOperationException)
                {
                }
            }
        }

        private OpenCifsShareSession[] DrainTrackedShareSessions()
        {
            OpenCifsShareSession[] shareSessions;

            lock (_SyncRoot)
            {
                shareSessions = new OpenCifsShareSession[_OpenShareSessions.Count];
                _OpenShareSessions.CopyTo(shareSessions);
                _OpenShareSessions.Clear();
            }

            return shareSessions;
        }

        private void ThrowIfDisposed()
        {
            if (_Disposed)
            {
                throw new OpenCifsClientStateException("The client has been disposed.");
            }
        }

        private readonly HashSet<OpenCifsShareSession> _OpenShareSessions = new HashSet<OpenCifsShareSession>();
        private readonly OpenCifsClientConnection _Connection;
        private readonly object _SyncRoot = new object();
        private bool _Disposed;
    }
}

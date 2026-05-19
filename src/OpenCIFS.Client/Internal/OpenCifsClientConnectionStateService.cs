namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Net.Sockets;
    using System.Threading.Tasks;
    using OpenCIFS.Transport;

    internal sealed class OpenCifsClientConnectionStateService
    {
        public OpenCifsClientConnectionStateService(OpenCifsClientOptions options)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _Session = new OpenCifsClientSession(options);
        }

        public IDictionary<uint, OpenCifsClientTreeHandle> ActiveTreesById
        {
            get
            {
                return _ActiveTreesById;
            }
        }

        public IDictionary<string, OpenCifsClientOpenHandle> ActiveOpensByKey
        {
            get
            {
                return _ActiveOpensByKey;
            }
        }

        public IReadOnlyCollection<OpenCifsClientTreeHandle> ActiveTreeHandles
        {
            get
            {
                return _ActiveTreesById.Values;
            }
        }

        public Guid ConnectionId
        {
            get
            {
                return _ConnectionId;
            }
        }

        public OpenCifsClientSession Session
        {
            get
            {
                return _Session;
            }
        }

        public FramedPipeConnection? Connection
        {
            get
            {
                return _Connection;
            }
        }

        public bool IsConnected
        {
            get
            {
                return _Connection != null;
            }
        }

        public bool IsAuthenticated
        {
            get
            {
                return _Session.IsAuthenticated;
            }
        }

        public bool IsDisposedOrAsyncDisposed
        {
            get
            {
                return _Disposed || _AsyncDisposed;
            }
        }

        public long GetSessionGeneration()
        {
            return _SessionGeneration;
        }

        public OpenCifsClientSession GetCurrentSession()
        {
            return _Session;
        }

        public void SetConnection(FramedPipeConnection? connection)
        {
            _Connection = connection;
        }

        public void SetTcpClient(TcpClient? tcpClient)
        {
            _TcpClient = tcpClient;
        }

        public void ThrowIfDisposed()
        {
            if (_Disposed || _AsyncDisposed)
            {
                throw new OpenCifsClientStateException("The client connection has been disposed.");
            }
        }

        public void EnsureNegotiatedConnection()
        {
            ThrowIfDisposed();

            if (_Connection == null || !_Session.IsNegotiated)
            {
                throw new OpenCifsClientStateException("A negotiated direct-TCP connection is required before authenticating.");
            }
        }

        public void EnsureAuthenticatedSession()
        {
            ThrowIfDisposed();

            if (_Connection == null || !_Session.IsAuthenticated || _Session.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated direct-TCP session is required before issuing low-level client operations.");
            }
        }

        public void ResetSession()
        {
            Guid clientGuid = _Session.ClientGuid;
            _SessionGeneration++;
            _Session = new OpenCifsClientSession(_Options, clientGuid);
        }

        public async Task ResetTransportAsync()
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

        public void MarkDisposed()
        {
            _Disposed = true;
        }

        public void MarkAsyncDisposed()
        {
            _AsyncDisposed = true;
        }

        private readonly OpenCifsClientOptions _Options;
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

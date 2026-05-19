namespace OpenCIFS.TestClient
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;

    internal sealed class TestClientConnectionCommands
    {
        public TestClientConnectionCommands(TestClientState state)
        {
            _State = state ?? throw new ArgumentNullException(nameof(state), "State cannot be null.");
        }

        public async Task ListSharesAsync(string[] parts, CancellationToken cancellationToken)
        {
            string serverName = parts.Length >= 2 ? parts[1] : _State.ServerName;
            bool canReuseConnectedClient =
                parts.Length < 2 &&
                _State.Client != null &&
                _State.Client.IsConnected &&
                _State.Client.IsAuthenticated &&
                StringComparer.OrdinalIgnoreCase.Equals(_State.Client.Settings.ServerName, _State.ServerName) &&
                _State.Client.Settings.ServerPort == _State.ServerPort;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _State.Client!;
                Console.WriteLine("[INFO] Enumerating shares through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to enumerate shares on " + serverName + ".");
                transientClient = CreateClientBuilder(serverName, _State.ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(cancellationToken).ConfigureAwait(false);

                if (!sharesResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(sharesResult.Exception!));
                    return;
                }

                OpenCifsRemoteShareInfo[] shares = sharesResult.Value!;
                Console.WriteLine("[OK] Share listing for " + serverName + ":");

                if (shares.Length == 0)
                {
                    Console.WriteLine("  (empty)");
                    return;
                }

                foreach (OpenCifsRemoteShareInfo share in shares.OrderBy(share => share.Name, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine("  " + share.ToDisplayString());
                }
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        public async Task PrintShareInfoAsync(string shareName, CancellationToken cancellationToken)
        {
            bool canReuseConnectedClient =
                _State.Client != null &&
                _State.Client.IsConnected &&
                _State.Client.IsAuthenticated;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _State.Client!;
                Console.WriteLine("[INFO] Querying share information through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to query share information for " + shareName + ".");
                transientClient = CreateClientBuilder(_State.ServerName, _State.ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync(shareName, cancellationToken).ConfigureAwait(false);

                if (!shareInfoResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(shareInfoResult.Exception!));
                    return;
                }

                OpenCifsRemoteShareInfo share = shareInfoResult.Value!;
                Console.WriteLine("[OK] Share information for " + share.Name + ":");
                Console.WriteLine("  Type           : " + share.Kind + (share.IsSpecial ? " special" : string.Empty) + (share.IsTemporary ? " temporary" : string.Empty));
                Console.WriteLine("  Remark         : " + TestClientConsoleHelpers.DisplayOrBlank(share.Remark));
                Console.WriteLine("  Permissions    : " + (share.Permissions?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Maximum Uses   : " + (share.MaximumUses?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Current Uses   : " + (share.CurrentUses?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Local Path     : " + TestClientConsoleHelpers.DisplayOrBlank(share.LocalPath));
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            if (_State.Client != null && _State.Client.IsConnected)
            {
                Console.WriteLine("[ERROR] A client connection is already active. Disconnect first.");
                return;
            }

            await DisconnectAsync().ConfigureAwait(false);

            OpenCifsClient client = CreateClientBuilder(_State.ServerName, _State.ServerPort).Build();
            OpenCifsClientCredential credential = CreateCredential();
            OpenCifsClientResult result = await client.TryConnectAsync(credential, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                await client.DisposeAsync().ConfigureAwait(false);
                return;
            }

            _State.Client = client;
            Console.WriteLine("[OK] Connected and authenticated.");
            Console.WriteLine("[OK] Negotiated dialect: " + (_State.Client.Session.NegotiatedDialect?.ToString() ?? "(none)"));
        }

        public async Task PipeTransceiveAsync(string pipeName, string requestText, CancellationToken cancellationToken)
        {
            bool canReuseConnectedClient =
                _State.Client != null &&
                _State.Client.IsConnected &&
                _State.Client.IsAuthenticated;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _State.Client!;
                Console.WriteLine("[INFO] Transceiving through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to transceive named pipe '" + pipeName + "'.");
                transientClient = CreateClientBuilder(_State.ServerName, _State.ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(requestText);
                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(pipeName, inputBytes, cancellationToken: cancellationToken).ConfigureAwait(false);

                if (!transceiveResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(transceiveResult.Exception!));
                    return;
                }

                Console.WriteLine("[OK] Pipe response from " + pipeName + ":");
                Console.WriteLine(Encoding.UTF8.GetString(transceiveResult.Value!));
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        public async Task DisconnectAsync()
        {
            await CloseShareAsync().ConfigureAwait(false);

            if (_State.Client == null)
            {
                return;
            }

            OpenCifsClient client = _State.Client;
            _State.Client = null;

            OpenCifsClientResult result = await client.TryDisconnectAsync(CancellationToken.None).ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
            }
            else
            {
                Console.WriteLine("[OK] Disconnected.");
            }

            await client.DisposeAsync().ConfigureAwait(false);
        }

        public async Task OpenShareAsync(string shareName, CancellationToken cancellationToken)
        {
            if (_State.Client == null || !_State.Client.IsConnected || !_State.Client.IsAuthenticated)
            {
                Console.WriteLine("[ERROR] Connect first.");
                return;
            }

            await CloseShareAsync().ConfigureAwait(false);
            OpenCifsClientResult<OpenCifsShareSession> result = await _State.Client.TryOpenShareAsync(shareName, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            _State.ShareSession = result.Value;
            _State.CurrentRemotePath = "/";
            Console.WriteLine("[OK] Opened share '" + shareName + "'.");
        }

        public async Task CloseShareAsync()
        {
            if (_State.ShareSession == null)
            {
                return;
            }

            OpenCifsShareSession shareSession = _State.ShareSession;
            _State.ShareSession = null;
            _State.CurrentRemotePath = "/";

            try
            {
                await shareSession.DisposeAsync().ConfigureAwait(false);
                Console.WriteLine("[OK] Closed share session.");
            }
            catch (OpenCifsClientException exception)
            {
                Console.WriteLine(FormatClientFailure(exception));
            }
        }

        private OpenCifsClientCredential CreateCredential()
        {
            return TestClientConnectionFactory.CreateCredential(_State.UserName, _State.UserDomain, _State.Password);
        }

        private OpenCifsClientBuilder CreateClientBuilder(string serverName, int serverPort)
        {
            return TestClientConnectionFactory.CreateClientBuilder(
                serverName,
                serverPort,
                _State.MinimumDialect,
                _State.MaximumDialect,
                _State.RequireSigning,
                _State.PreferEncryption,
                _State.ConnectTimeoutMs);
        }

        private static string FormatClientFailure(OpenCifsClientException exception)
        {
            return TestClientConsoleHelpers.FormatClientFailure(exception);
        }

        private readonly TestClientState _State;
    }
}

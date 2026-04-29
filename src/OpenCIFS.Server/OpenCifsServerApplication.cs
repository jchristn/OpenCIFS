namespace OpenCIFS.Server
{
    using System;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Managed direct-TCP application wrapper for OpenCIFS server listeners.
    /// </summary>
    public sealed class OpenCifsServerApplication : IAsyncDisposable
    {
        /// <summary>
        /// Initialize a managed server application.
        /// </summary>
        /// <param name="options">Listener options.</param>
        /// <param name="server">Underlying direct-TCP server.</param>
        public OpenCifsServerApplication(OpenCifsServerOptions options, OpenCifsDirectTcpServer server)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _Server = server ?? throw new ArgumentNullException(nameof(server), "Server cannot be null.");
        }

        /// <summary>
        /// Listener options used by the application.
        /// </summary>
        public OpenCifsServerOptions Options { get; }

        /// <summary>
        /// Whether the managed application currently owns a running listener task.
        /// </summary>
        public bool IsRunning
        {
            get
            {
                return _RunTask != null;
            }
        }

        /// <summary>
        /// Run the underlying server until cancellation is requested.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public Task RunAsync(CancellationToken cancellationToken = default)
        {
            return _Server.RunAsync(cancellationToken);
        }

        /// <summary>
        /// Start the listener in the background and wait until it accepts probe connections.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for startup waiting.</param>
        /// <returns>Completion task.</returns>
        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_RunTask != null)
            {
                throw new InvalidOperationException("The server application is already running.");
            }

            _RunCancellationTokenSource = new CancellationTokenSource();
            _RunTask = _Server.RunAsync(_RunCancellationTokenSource.Token);

            try
            {
                await WaitForListenerAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await StopAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Stop the managed listener when it is running.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for shutdown waiting.</param>
        /// <returns>Completion task.</returns>
        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            if (_RunTask == null)
            {
                return;
            }

            Task runTask = _RunTask;
            CancellationTokenSource runCancellationTokenSource = _RunCancellationTokenSource!;
            _RunTask = null;
            _RunCancellationTokenSource = null;
            runCancellationTokenSource.Cancel();

            try
            {
                await runTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                runCancellationTokenSource.Dispose();
            }
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
        }

        private async Task WaitForListenerAsync(CancellationToken cancellationToken)
        {
            string probeHost = DetermineProbeHost(Options.BindAddress);

            for (int attempt = 0; attempt < 40; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (_RunTask != null && _RunTask.IsCompleted)
                {
                    await _RunTask.ConfigureAwait(false);
                }

                using TcpClient tcpClient = new TcpClient();

                try
                {
                    using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(250);
                    using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
                    await tcpClient.ConnectAsync(probeHost, Options.BindPort, linkedTokenSource.Token).ConfigureAwait(false);
                    return;
                }
                catch (SocketException)
                {
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            if (_RunTask != null && _RunTask.IsCompleted)
            {
                await _RunTask.ConfigureAwait(false);
            }

            throw new InvalidOperationException("Timed out waiting for the managed OpenCIFS listener to accept direct-TCP probe connections.");
        }

        private static string DetermineProbeHost(string bindAddress)
        {
            if (string.IsNullOrWhiteSpace(bindAddress))
            {
                return "127.0.0.1";
            }

            switch (bindAddress.Trim())
            {
                case "0.0.0.0":
                case "::":
                case "*":
                case "+":
                    return "127.0.0.1";
                default:
                    return bindAddress;
            }
        }

        private CancellationTokenSource? _RunCancellationTokenSource;
        private Task? _RunTask;
        private readonly OpenCifsDirectTcpServer _Server;
    }
}

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
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
        /// <param name="availableShares">Immutable snapshots for the shares exposed by this application.</param>
        public OpenCifsServerApplication(OpenCifsServerOptions options, OpenCifsDirectTcpServer server, IReadOnlyList<OpenCifsServerShareInfo> availableShares)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _Server = server ?? throw new ArgumentNullException(nameof(server), "Server cannot be null.");
            _AvailableShares = CopyAvailableShares(availableShares);
        }

        /// <summary>
        /// Listener options used by the application.
        /// </summary>
        public OpenCifsServerOptions Options { get; }

        /// <summary>
        /// Immutable snapshots for the shares exposed by this managed application.
        /// </summary>
        public IReadOnlyList<OpenCifsServerShareInfo> AvailableShares
        {
            get
            {
                return _AvailableShares;
            }
        }

        /// <summary>
        /// Whether the managed application currently owns a running listener task.
        /// </summary>
        public bool IsRunning
        {
            get
            {
                return _RunTask != null || _ForegroundRunInProgress;
            }
        }

        /// <summary>
        /// Get immutable snapshots for the shares exposed by this managed application.
        /// </summary>
        /// <returns>Available share snapshots.</returns>
        public IReadOnlyList<OpenCifsServerShareInfo> GetAvailableShares()
        {
            return _AvailableShares;
        }

        /// <summary>
        /// Run the underlying server until cancellation is requested.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public Task RunAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_RunTask != null || _ForegroundRunInProgress)
            {
                throw new OpenCifsServerStateException("The server application is already running.");
            }

            return RunForegroundAsync(cancellationToken);
        }

        /// <summary>
        /// Run the underlying server until cancellation is requested and preserve typed server failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsServerResult> TryRunAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsServerResultFactory.TryAsync(() => RunAsync(cancellationToken));
        }

        /// <summary>
        /// Start the listener in the background and wait until it accepts probe connections.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for startup waiting.</param>
        /// <returns>Completion task.</returns>
        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_RunTask != null || _ForegroundRunInProgress)
            {
                throw new OpenCifsServerStateException("The server application is already running.");
            }

            _RunCancellationTokenSource = new CancellationTokenSource();
            _RunTask = _Server.RunAsync(_RunCancellationTokenSource.Token);

            try
            {
                await WaitForListenerAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException exception)
            {
                await CleanupFailedBackgroundStartAsync().ConfigureAwait(false);
                throw new OpenCifsServerStateException("Failed to start the managed OpenCIFS listener.", exception);
            }
            catch (ObjectDisposedException exception)
            {
                await CleanupFailedBackgroundStartAsync().ConfigureAwait(false);
                throw new OpenCifsServerStateException("Failed to start the managed OpenCIFS listener because the underlying socket resources were disposed.", exception);
            }
            catch
            {
                await CleanupFailedBackgroundStartAsync().ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Start the listener in the background and preserve typed server failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for startup waiting.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsServerResult> TryStartAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsServerResultFactory.TryAsync(() => StartAsync(cancellationToken));
        }

        /// <summary>
        /// Stop the managed listener when it is running.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for shutdown waiting.</param>
        /// <returns>Completion task.</returns>
        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_ForegroundRunInProgress)
            {
                throw new OpenCifsServerStateException("The server application is running through RunAsync and must be stopped by canceling the run token.");
            }

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

        /// <summary>
        /// Stop the managed listener and preserve typed server failures in a non-throwing result envelope.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for shutdown waiting.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsServerResult> TryStopAsync(CancellationToken cancellationToken = default)
        {
            return OpenCifsServerResultFactory.TryAsync(() => StopAsync(cancellationToken));
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            if (_Disposed)
            {
                return;
            }

            if (_RunTask != null)
            {
                await StopAsync().ConfigureAwait(false);
            }

            _Disposed = true;
        }

        private async Task RunForegroundAsync(CancellationToken cancellationToken)
        {
            _ForegroundRunInProgress = true;

            try
            {
                await _Server.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException exception)
            {
                throw new OpenCifsServerStateException("Failed to start the managed OpenCIFS listener.", exception);
            }
            catch (ObjectDisposedException exception)
            {
                throw new OpenCifsServerStateException("Failed to run the managed OpenCIFS listener because the underlying socket resources were disposed.", exception);
            }
            finally
            {
                _ForegroundRunInProgress = false;
            }
        }

        private async Task CleanupFailedBackgroundStartAsync()
        {
            if (_RunTask == null)
            {
                return;
            }

            Task runTask = _RunTask;
            CancellationTokenSource? runCancellationTokenSource = _RunCancellationTokenSource;
            _RunTask = null;
            _RunCancellationTokenSource = null;

            if (runCancellationTokenSource != null)
            {
                runCancellationTokenSource.Cancel();
            }

            try
            {
                await runTask.ConfigureAwait(false);
            }
            catch
            {
            }
            finally
            {
                runCancellationTokenSource?.Dispose();
            }
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

            throw new OpenCifsServerStateException("Timed out waiting for the managed OpenCIFS listener to accept direct-TCP probe connections.");
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

        private static OpenCifsServerShareInfo[] CopyAvailableShares(IReadOnlyList<OpenCifsServerShareInfo> availableShares)
        {
            if (availableShares == null)
            {
                throw new ArgumentNullException(nameof(availableShares), "AvailableShares cannot be null.");
            }

            OpenCifsServerShareInfo[] copies = new OpenCifsServerShareInfo[availableShares.Count];

            for (int index = 0; index < availableShares.Count; index++)
            {
                copies[index] = availableShares[index] ?? throw new ArgumentException("AvailableShares cannot contain null entries.", nameof(availableShares));
            }

            return copies;
        }

        private void ThrowIfDisposed()
        {
            if (_Disposed)
            {
                throw new OpenCifsServerStateException("The server application has been disposed.");
            }
        }

        private readonly OpenCifsServerShareInfo[] _AvailableShares;
        private bool _Disposed;
        private bool _ForegroundRunInProgress;
        private CancellationTokenSource? _RunCancellationTokenSource;
        private Task? _RunTask;
        private readonly OpenCifsDirectTcpServer _Server;
    }
}


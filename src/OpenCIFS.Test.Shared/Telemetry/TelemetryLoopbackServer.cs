namespace OpenCIFS.Telemetry.Tests.Shared
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Client.Tests.Shared;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;

    /// <summary>
    /// Direct-TCP loopback server with a temporary file-system share, used by the telemetry suite.
    /// Owns the share directory and the listener, and releases both on <see cref="DisposeAsync" />.
    /// </summary>
    internal sealed class TelemetryLoopbackServer : IAsyncDisposable
    {
        private const string PortReservationLockName = "OpenCIFS.DirectTcpTestPortReservation";

        private TelemetryLoopbackServer(string sharePath, int port)
        {
            SharePath = sharePath;
            Port = port;
        }

        internal string SharePath { get; }

        internal int Port { get; }

        internal static async Task<TelemetryLoopbackServer> StartAsync(CancellationToken token)
        {
            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsTelemetry_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sharePath);

            // Hold the same cross-process port-reservation lock as the other direct-TCP suites, but only from picking the
            // port until the listener is accepting, so concurrent test hosts never race for the same ephemeral port.
            using CrossProcessTestLock portLock = new CrossProcessTestLock(PortReservationLockName);

            if (!portLock.WaitOne(TimeSpan.FromSeconds(30)))
            {
                throw new InvalidOperationException("Timed out waiting to reserve the shared direct-TCP test port allocator.");
            }

            TelemetryLoopbackServer? server = null;

            try
            {
                TcpListener probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                int port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();
                server = new TelemetryLoopbackServer(sharePath, port);
                await server.StartListenerAsync(token).ConfigureAwait(false);
                return server;
            }
            catch
            {
                if (server != null)
                {
                    await server.DisposeAsync().ConfigureAwait(false);
                }

                throw;
            }
            finally
            {
                portLock.Release();
            }
        }

        internal OpenCifsClient BuildClient(int connectTimeoutMs = 5000)
        {
            return new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", Port)
                .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                .WithConnectTimeoutMs(connectTimeoutMs)
                .Build();
        }

        internal async Task StopListenerAsync()
        {
            CancellationTokenSource? cancellationTokenSource = _CancellationTokenSource;
            Task? serverTask = _ServerTask;
            _CancellationTokenSource = null;
            _ServerTask = null;

            if (cancellationTokenSource == null || serverTask == null)
            {
                return;
            }

            cancellationTokenSource.Cancel();

            try
            {
                await serverTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                cancellationTokenSource.Dispose();
            }
        }

        public async ValueTask DisposeAsync()
        {
            await StopListenerAsync().ConfigureAwait(false);

            try
            {
                if (Directory.Exists(SharePath))
                {
                    Directory.Delete(SharePath, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private async Task StartListenerAsync(CancellationToken token)
        {
            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = Port
            });
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = SharePath,
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });

            _CancellationTokenSource = new CancellationTokenSource();
            _ServerTask = builder.BuildDirectTcpServer().RunAsync(_CancellationTokenSource.Token);
            await ClientTestSupport.WaitForDirectTcpServerAsync(Port, token).ConfigureAwait(false);
        }

        private CancellationTokenSource? _CancellationTokenSource;
        private Task? _ServerTask;
    }
}

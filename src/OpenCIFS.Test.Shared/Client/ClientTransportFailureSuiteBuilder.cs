namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;

    /// <summary>
    /// Transport-loss and connect-timeout coverage for the primary client surface.
    /// </summary>
    internal static class ClientTransportFailureSuiteBuilder
    {
        private const string SuiteId = "Client.TransportFailure";

        /// <summary>
        /// Build the transport-failure suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientTransportFailureSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: SuiteId,
                displayName: "Client transport loss, connect timeout, and cancellation reporting",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientReportsTypedTransportExceptionAfterServerRestartAndReconnects",
                        displayName: "Client reports a typed transport exception after the server restarts between operations, reports disconnected, and reconnects",
                        executeAsync: RestartBetweenOperationsAsync),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientFailsInFlightOperationPromptlyWhenServerIsClosed",
                        displayName: "Client fails an in-flight operation promptly with a transport exception when the server is closed",
                        executeAsync: ServerClosedWithOperationInFlightAsync),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientConnectToClosedPortReportsTransportExceptionNotCancellation",
                        displayName: "Client connect to a closed port reports a transport exception instead of cancellation",
                        executeAsync: ConnectToClosedPortAsync),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientConnectToSilentEndpointReportsTimeoutNotCancellation",
                        displayName: "Client connect to a silent or black-holed endpoint reports a timeout transport exception instead of cancellation",
                        executeAsync: ConnectToSilentEndpointAsync),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientConnectCancelledByCallerStillReportsOperationCanceled",
                        displayName: "Client connect cancelled by the caller still reports OperationCanceledException",
                        executeAsync: CallerCancelledConnectAsync),
                });
        }

        private static async Task RestartBetweenOperationsAsync(CancellationToken token)
        {
            string sharePath = CreateSharePath();
            int port = AllocateTcpPort();
            RawServer? server = null;

            try
            {
                server = await RawServer.StartAsync(sharePath, port, token).ConfigureAwait(false);
                await using OpenCifsClient client = BuildClient(port, connectTimeoutMs: 5000);
                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                await share.Files.WriteAllBytesAsync("before.txt", new byte[] { 1, 2, 3 }, token).ConfigureAwait(false);

                await server.StopAsync().ConfigureAwait(false);
                server = await RawServer.StartAsync(sharePath, port, token).ConfigureAwait(false);

                await WaitUntilAsync(() => !client.IsConnected, TimeSpan.FromSeconds(10), token).ConfigureAwait(false);
                TestAssertions.False(client.IsConnected, "Expected IsConnected to report false after the server restarted.");
                TestAssertions.False(client.IsAuthenticated, "Expected IsAuthenticated to report false after the server restarted.");

                OpenCifsClientTransportException exception = await ExpectTransportExceptionAsync(
                    () => share.Files.ReadAllBytesAsync("before.txt", token)).ConfigureAwait(false);
                TestAssertions.Equal(OpenCifsErrorCategory.IoError, exception.Category, "Expected transport failures to normalize to IoError.");
                TestAssertions.False(exception.IsTimeout, "Expected a peer close not to be reported as a timeout.");
                TestAssertions.True(exception.InnerException != null, "Expected the original transport failure as the inner exception.");

                OpenCifsClientResult<byte[]> tryResult = await share.Files.TryReadAllBytesAsync("before.txt", token).ConfigureAwait(false);
                TestAssertions.False(tryResult.IsSuccess, "Expected the Try envelope to report failure on a dead connection.");
                TestAssertions.True(tryResult.Exception is OpenCifsClientTransportException, "Expected the Try envelope to carry the transport exception.");
                TestAssertions.Equal(OpenCifsErrorCategory.IoError, tryResult.ErrorCategory!.Value, "Expected the Try envelope category to be IoError.");

                await ExpectTransportExceptionAsync(() => client.EchoAsync(token)).ConfigureAwait(false);
                await client.DisconnectAsync(token).ConfigureAwait(false);

                await using OpenCifsClient freshClient = BuildClient(port, connectTimeoutMs: 5000);
                await freshClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                await using OpenCifsShareSession freshShare = await freshClient.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                AssertBytes(new byte[] { 1, 2, 3 }, await freshShare.Files.ReadAllBytesAsync("before.txt", token).ConfigureAwait(false), "Expected a new client to connect and read after the restart.");

                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                TestAssertions.True(client.IsConnected && client.IsAuthenticated, "Expected the original client to reconnect after the transport loss.");
                await using OpenCifsShareSession reopened = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                AssertBytes(new byte[] { 1, 2, 3 }, await reopened.Files.ReadAllBytesAsync("before.txt", token).ConfigureAwait(false), "Expected the reconnected client to read the file.");
            }
            finally
            {
                if (server != null)
                {
                    await server.StopAsync().ConfigureAwait(false);
                }

                ReleaseDirectTcpPortReservation();
                DeleteSharePath(sharePath);
            }
        }

        private static async Task ServerClosedWithOperationInFlightAsync(CancellationToken token)
        {
            string sharePath = CreateSharePath();
            int port = AllocateTcpPort();
            RawServer? server = null;

            try
            {
                server = await RawServer.StartAsync(sharePath, port, token).ConfigureAwait(false);
                await using OpenCifsClient client = BuildClient(port, connectTimeoutMs: 5000);
                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                await share.Directories.CreateAsync("watched", token).ConfigureAwait(false);

                Task<OpenCifsClientChangeNotification[]> pending = share.Directories.WaitForChangeAsync("watched", FileNotifyChangeFilter.FileName, cancellationToken: token);
                await Task.Delay(300, token).ConfigureAwait(false);
                TestAssertions.False(pending.IsCompleted, "Expected the change notification to be pending while the server is alive.");

                Stopwatch stopwatch = Stopwatch.StartNew();
                Task stopTask = server.StopAsync();
                server = null;
                Task completed = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(10), token)).ConfigureAwait(false);
                TestAssertions.True(completed == pending, "Expected the in-flight operation to fail promptly after the server closed instead of hanging.");
                await ExpectTransportExceptionAsync(() => pending).ConfigureAwait(false);
                TestAssertions.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "Expected the in-flight failure within ten seconds.");
                await stopTask.ConfigureAwait(false);
                TestAssertions.False(client.IsConnected, "Expected IsConnected to report false after the in-flight transport failure.");

                await ExpectTransportExceptionAsync(() => share.Metadata.ExistsAsync("watched", token)).ConfigureAwait(false);
            }
            finally
            {
                if (server != null)
                {
                    await server.StopAsync().ConfigureAwait(false);
                }

                ReleaseDirectTcpPortReservation();
                DeleteSharePath(sharePath);
            }
        }

        private static async Task ConnectToClosedPortAsync(CancellationToken token)
        {
            int port = AllocateTcpPort();

            try
            {
                await using OpenCifsClient client = BuildClient(port, connectTimeoutMs: 2000);
                Stopwatch stopwatch = Stopwatch.StartNew();
                OpenCifsClientTransportException exception = await ExpectTransportExceptionAsync(
                    () => client.ConnectAsync(CreateCredential(), token)).ConfigureAwait(false);
                TestAssertions.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "Expected a closed-port connect to fail within the connect timeout.");
                TestAssertions.True(
                    exception.InnerException is SocketException || (exception.IsTimeout && exception.InnerException is TimeoutException),
                    "Expected a refused connection (SocketException) or a connect timeout (TimeoutException) as the inner exception.");
                TestAssertions.False(client.IsConnected, "Expected a failed connect to leave the client disconnected.");

                OpenCifsClientResult tryResult = await client.TryConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                TestAssertions.False(tryResult.IsSuccess, "Expected TryConnectAsync to report a closed-port failure.");
                TestAssertions.True(tryResult.Exception is OpenCifsClientTransportException, "Expected TryConnectAsync to carry the transport exception.");
                TestAssertions.Equal(OpenCifsErrorCategory.IoError, tryResult.ErrorCategory!.Value, "Expected TryConnectAsync to report IoError.");
            }
            finally
            {
                ReleaseDirectTcpPortReservation();
            }
        }

        private static async Task ConnectToSilentEndpointAsync(CancellationToken token)
        {
            // A listener that completes the TCP handshake but never answers NEGOTIATE behaves like a black hole.
            TcpListener silentListener = new TcpListener(IPAddress.Loopback, 0);
            silentListener.Start();

            try
            {
                int port = ((IPEndPoint)silentListener.LocalEndpoint).Port;
                await using OpenCifsClient client = BuildClient(port, connectTimeoutMs: 1000);
                Stopwatch stopwatch = Stopwatch.StartNew();
                OpenCifsClientTransportException exception = await ExpectTransportExceptionAsync(
                    () => client.ConnectAsync(CreateCredential(), token)).ConfigureAwait(false);
                TestAssertions.True(exception.IsTimeout, "Expected a silent endpoint to be reported as a connect timeout.");
                TestAssertions.True(exception.InnerException is TimeoutException, "Expected a TimeoutException as the inner exception.");
                TestAssertions.True(stopwatch.Elapsed < TimeSpan.FromSeconds(8), "Expected the connect timeout to be honored.");
                TestAssertions.False(client.IsConnected, "Expected a timed-out connect to leave the client disconnected.");

                OpenCifsClientResult tryResult = await client.TryConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                TestAssertions.False(tryResult.IsSuccess, "Expected TryConnectAsync to report the timeout.");
                TestAssertions.True(tryResult.Exception is OpenCifsClientTransportException transport && transport.IsTimeout, "Expected TryConnectAsync to carry the timeout transport exception.");
            }
            finally
            {
                silentListener.Stop();
            }

            // A non-routable address exercises the TCP-level connect path; depending on the host network it either times
            // out or is rejected immediately, but it must never surface as cancellation.
            await using OpenCifsClient blackHoleClient = new OpenCifsClientBuilder()
                .WithServer("10.255.255.1", 445)
                .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                .WithConnectTimeoutMs(1000)
                .Build();
            Stopwatch blackHoleStopwatch = Stopwatch.StartNew();
            await ExpectTransportExceptionAsync(() => blackHoleClient.ConnectAsync(CreateCredential(), token)).ConfigureAwait(false);
            TestAssertions.True(blackHoleStopwatch.Elapsed < TimeSpan.FromSeconds(8), "Expected the black-holed connect to honor the connect timeout.");
        }

        private static async Task CallerCancelledConnectAsync(CancellationToken token)
        {
            TcpListener silentListener = new TcpListener(IPAddress.Loopback, 0);
            silentListener.Start();

            try
            {
                int port = ((IPEndPoint)silentListener.LocalEndpoint).Port;
                await using OpenCifsClient client = BuildClient(port, connectTimeoutMs: 30000);
                using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
                cancellation.CancelAfter(TimeSpan.FromMilliseconds(300));
                Stopwatch stopwatch = Stopwatch.StartNew();
                Exception? thrown = null;

                try
                {
                    await client.ConnectAsync(CreateCredential(), cancellation.Token).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    thrown = exception;
                }

                TestAssertions.True(thrown is OperationCanceledException, "Expected caller cancellation during connect to surface as OperationCanceledException but got " + (thrown?.GetType().FullName ?? "no exception") + ".");
                TestAssertions.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "Expected caller cancellation to end the connect promptly.");
                TestAssertions.False(client.IsConnected, "Expected a cancelled connect to leave the client disconnected.");
            }
            finally
            {
                silentListener.Stop();
            }
        }

        private static OpenCifsClient BuildClient(int port, int connectTimeoutMs)
        {
            return new OpenCifsClientBuilder()
                .WithServer("127.0.0.1", port)
                .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                .WithConnectTimeoutMs(connectTimeoutMs)
                .Build();
        }

        private static async Task<OpenCifsClientTransportException> ExpectTransportExceptionAsync(Func<Task> action)
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (OpenCifsClientTransportException exception)
            {
                return exception;
            }
            catch (Exception exception)
            {
                throw new InvalidOperationException("Expected OpenCifsClientTransportException but got " + exception.GetType().FullName + ": " + exception.Message, exception);
            }

            throw new InvalidOperationException("Expected OpenCifsClientTransportException but the operation succeeded.");
        }

        private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout, CancellationToken token)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            while (!condition() && stopwatch.Elapsed < timeout)
            {
                await Task.Delay(25, token).ConfigureAwait(false);
            }
        }

        private static void AssertBytes(byte[] expected, byte[] actual, string message)
        {
            TestAssertions.SequenceEqual(expected, actual, message);
        }

        private static string CreateSharePath()
        {
            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsTransportFailure_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sharePath);
            return sharePath;
        }

        private static void DeleteSharePath(string sharePath)
        {
            try
            {
                if (Directory.Exists(sharePath))
                {
                    Directory.Delete(sharePath, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private sealed class RawServer
        {
            private RawServer(CancellationTokenSource cancellationTokenSource, Task serverTask)
            {
                _CancellationTokenSource = cancellationTokenSource;
                _ServerTask = serverTask;
            }

            internal static async Task<RawServer> StartAsync(string sharePath, int port, CancellationToken token)
            {
                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                {
                    ServerName = "127.0.0.1",
                    BindAddress = "127.0.0.1",
                    BindPort = port
                });
                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                {
                    ShareName = TestEnvironmentDefaults.DefaultShareName,
                    RootPath = sharePath,
                    CreateRootIfMissing = true
                });
                builder.AddAccount(new OpenCifsServerAccount
                {
                    UserName = TestEnvironmentDefaults.DefaultUserName,
                    UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                    Password = TestEnvironmentDefaults.DefaultPassword
                });

                CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
                Task serverTask = builder.BuildDirectTcpServer().RunAsync(cancellationTokenSource.Token);
                RawServer server = new RawServer(cancellationTokenSource, serverTask);

                try
                {
                    await WaitForDirectTcpServerAsync(port, token).ConfigureAwait(false);
                }
                catch
                {
                    await server.StopAsync().ConfigureAwait(false);
                    throw;
                }

                return server;
            }

            internal async Task StopAsync()
            {
                if (_Stopped)
                {
                    return;
                }

                _Stopped = true;
                _CancellationTokenSource.Cancel();

                try
                {
                    await _ServerTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    _CancellationTokenSource.Dispose();
                }
            }

            private readonly CancellationTokenSource _CancellationTokenSource;
            private readonly Task _ServerTask;
            private bool _Stopped;
        }
    }
}

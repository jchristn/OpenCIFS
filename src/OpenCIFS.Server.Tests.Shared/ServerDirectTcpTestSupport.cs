namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;

    internal static class ServerDirectTcpTestSupport
    {
        private const string DirectTcpPortReservationSemaphoreName = "OpenCIFS.DirectTcpTestPortReservation";
        private static readonly AsyncLocal<DirectTcpPortReservation?> _CurrentDirectTcpPortReservation = new AsyncLocal<DirectTcpPortReservation?>();

        internal static int AllocateTcpPort()
        {
            if (_CurrentDirectTcpPortReservation.Value != null)
            {
                throw new InvalidOperationException("A direct-TCP test port is already reserved on this async flow.");
            }

            Semaphore? semaphore = new Semaphore(initialCount: 1, maximumCount: 1, name: DirectTcpPortReservationSemaphoreName);
            bool lockTaken = false;

            try
            {
                lockTaken = semaphore.WaitOne(TimeSpan.FromSeconds(30));

                if (!lockTaken)
                {
                    throw new InvalidOperationException("Timed out waiting to reserve the shared direct-TCP test port allocator.");
                }

                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();

                try
                {
                    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    _CurrentDirectTcpPortReservation.Value = new DirectTcpPortReservation(semaphore, port);
                    semaphore = null;
                    return port;
                }
                finally
                {
                    listener.Stop();
                }
            }
            catch
            {
                if (semaphore != null)
                {
                    if (lockTaken)
                    {
                        semaphore.Release();
                    }

                    semaphore.Dispose();
                }

                throw;
            }
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(port, _ => { }, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3,
                _ => { },
                cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3: true,
                exceptionHandler,
                cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            DirectTcpPortReservation reservation = GetDirectTcpPortReservation(port);
            OpenCifsDirectTcpServer server = new OpenCifsDirectTcpServer(new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = port,
                RequireEncryptionForSmb3 = requireEncryptionForSmb3
            }, exceptionHandler: exceptionHandler);
            CancellationTokenSource serverCancellationTokenSource = new CancellationTokenSource();
            Task serverTask = server.RunAsync(serverCancellationTokenSource.Token);

            try
            {
                await WaitForTcpListenerStateAsync(reservation.Port, shouldAcceptConnections: true, cancellationToken).ConfigureAwait(false);
                return new DirectTcpServerHandle(serverCancellationTokenSource, serverTask);
            }
            catch
            {
                serverCancellationTokenSource.Cancel();

                try
                {
                    await serverTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    serverCancellationTokenSource.Dispose();
                    ReleaseDirectTcpPortReservation();
                }

                throw;
            }
        }

        internal static async Task StopDirectTcpServerAsync(CancellationTokenSource serverCancellationTokenSource, Task serverTask)
        {
            serverCancellationTokenSource.Cancel();

            try
            {
                await serverTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                serverCancellationTokenSource.Dispose();
                ReleaseDirectTcpPortReservation();
            }
        }

        internal static void ReleaseDirectTcpPortReservation()
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;
            _CurrentDirectTcpPortReservation.Value = null;

            if (reservation == null)
            {
                return;
            }

            reservation.Semaphore.Release();
            reservation.Semaphore.Dispose();
        }

        internal static async Task WriteDirectTcpFrameAsync(NetworkStream stream, byte[] payload, CancellationToken cancellationToken)
        {
            byte[] headerBytes = new DirectTcpFrameHeader
            {
                Length = payload.Length
            }.ToByteArray();
            await stream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<byte[]> ReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[]? payload = await TryReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);

            if (payload == null)
            {
                throw new InvalidOperationException("Expected a Direct-TCP response frame but the connection closed instead.");
            }

            return payload;
        }

        internal static async Task<byte[]?> TryReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[] headerBytes = new byte[DirectTcpFrameHeader.Size];
            int headerRead = await ReadExactOrDetectCloseAsync(stream, headerBytes, cancellationToken).ConfigureAwait(false);

            if (headerRead == 0)
            {
                return null;
            }

            DirectTcpFrameHeader header = DirectTcpFrameHeader.ReadFrom(headerBytes);
            byte[] payload = new byte[header.Length];
            int payloadRead = await ReadExactOrDetectCloseAsync(stream, payload, cancellationToken).ConfigureAwait(false);

            if (payloadRead == 0)
            {
                throw new InvalidOperationException("The Direct-TCP connection closed before the response payload was received.");
            }

            return payload;
        }

        internal static async Task AssertNegotiatesDirectTcpRequestAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            using TcpClient tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken).ConfigureAwait(false);
            using NetworkStream stream = tcpClient.GetStream();
            await WriteDirectTcpFrameAsync(stream, requestPayload, cancellationToken).ConfigureAwait(false);

            byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
            TestAssertions.Equal(1, responsePacket.Entries.Count, "Expected a single negotiate response entry.");
            TestAssertions.Equal(Smb2Command.Negotiate, responsePacket.Entries[0].Header.Command, "Expected a negotiate response command.");
            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the negotiate response status to be success.");

            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimResponsePayload(
                Smb2Command.Negotiate,
                responsePacket.Entries[0].Payload);
            Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(trimmedPayload);
            Smb2NegotiateResponseValidator.Validate(response);
            TestAssertions.Equal(SmbDialect.Smb21, response.Dialect, "Expected the direct-TCP negotiate response to resolve to SMB 2.1.");
        }

        internal static async Task<byte[]?> SendMalformedDirectTcpFrameAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            using TcpClient tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken).ConfigureAwait(false);
            using NetworkStream stream = tcpClient.GetStream();

            if (requestPayload.Length == 0)
            {
                byte[] zeroLengthHeaderBytes = new byte[DirectTcpFrameHeader.Size];
                await stream.WriteAsync(zeroLengthHeaderBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await WriteDirectTcpFrameAsync(stream, requestPayload, cancellationToken).ConfigureAwait(false);
            }

            using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);

            try
            {
                return await TryReadDirectTcpFramePayloadAsync(stream, linkedTokenSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeoutTokenSource.IsCancellationRequested)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (OverflowException)
            {
                return null;
            }
            catch (ProtocolEncodingException)
            {
                return null;
            }
        }

        internal static async Task<int> ReadExactOrDetectCloseAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            int offset = 0;

            while (offset < buffer.Length)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);

                if (count == 0)
                {
                    if (offset == 0)
                    {
                        return 0;
                    }

                    throw new InvalidOperationException("The Direct-TCP connection closed before the frame completed.");
                }

                offset += count;
            }

            return offset;
        }

        internal static async Task WaitForTcpListenerStateAsync(int port, bool shouldAcceptConnections, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < 40; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using TcpClient tcpClient = new TcpClient();

                try
                {
                    using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(250);
                    using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
                    await tcpClient.ConnectAsync(IPAddress.Loopback, port, linkedTokenSource.Token).ConfigureAwait(false);

                    if (shouldAcceptConnections)
                    {
                        return;
                    }
                }
                catch (SocketException)
                {
                    if (!shouldAcceptConnections)
                    {
                        return;
                    }
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    if (!shouldAcceptConnections)
                    {
                        return;
                    }
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            throw new InvalidOperationException(
                shouldAcceptConnections
                    ? "Timed out waiting for the managed server listener to accept direct-TCP probe connections."
                    : "Timed out waiting for the managed server listener to stop accepting direct-TCP probe connections.");
        }

        private static DirectTcpPortReservation GetDirectTcpPortReservation(int port)
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;

            if (reservation == null || reservation.Port != port)
            {
                throw new InvalidOperationException("Expected a reserved direct-TCP test port before starting the server.");
            }

            return reservation;
        }

        private sealed class DirectTcpPortReservation
        {
            public DirectTcpPortReservation(Semaphore semaphore, int port)
            {
                Semaphore = semaphore ?? throw new ArgumentNullException(nameof(semaphore));
                Port = port;
            }

            public Semaphore Semaphore { get; }

            public int Port { get; }
        }
    }
}

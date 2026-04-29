namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Channels;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Transport;

    /// <summary>
    /// Direct-TCP SMB server loop that exposes one connection-scoped <see cref="OpenCifsServerHost" /> per accepted socket while sharing server-wide state.
    /// </summary>
    public sealed class OpenCifsDirectTcpServer
    {
        /// <summary>
        /// Initialize the direct-TCP server.
        /// </summary>
        /// <param name="options">Listener and default host options.</param>
        /// <param name="hostFactory">Optional per-connection host factory.</param>
        /// <param name="exceptionHandler">Optional callback for per-connection exceptions.</param>
        public OpenCifsDirectTcpServer(OpenCifsServerOptions options, Func<OpenCifsServerHost>? hostFactory = null, Action<Exception>? exceptionHandler = null)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
            _HostFactory = hostFactory ?? (() => new OpenCifsServerHost(_Options, sharedState));
            _ExceptionHandler = exceptionHandler ?? (_ => { });
        }

        /// <summary>
        /// Run the listener until cancellation is requested.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            if (_IsRunning)
            {
                throw new InvalidOperationException("The direct-TCP server is already running.");
            }

            _IsRunning = true;

            try
            {
                IPAddress bindAddress = ResolveBindAddress(_Options.BindAddress);
                TcpListener listener = new TcpListener(bindAddress, _Options.BindPort);
                listener.Start();

                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        TcpClient client;

                        try
                        {
                            client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        catch (SocketException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        TrackConnectionTask(HandleClientAsync(client, cancellationToken));
                    }
                }
                finally
                {
                    listener.Stop();
                    await WaitForTrackedConnectionsAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                _IsRunning = false;
            }
        }

        private void TrackConnectionTask(Task task)
        {
            lock (_ConnectionSync)
            {
                _ConnectionTasks.Add(task);
            }
        }

        private async Task WaitForTrackedConnectionsAsync()
        {
            Task[] tasks;

            lock (_ConnectionSync)
            {
                tasks = _ConnectionTasks.ToArray();
                _ConnectionTasks.Clear();
            }

            if (tasks.Length == 0)
            {
                return;
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            using (client)
            {
                client.NoDelay = true;
                using NetworkStream networkStream = client.GetStream();
                await using FramedPipeConnection connection = FramedPipeConnection.Create(networkStream, new DirectTcpFrameProtocol());
                OpenCifsServerHost host = _HostFactory();
                connection.Start();

                try
                {
                    Task<byte[]> readTask = connection.ReadAsync(cancellationToken).AsTask();
                    Task asyncResponseTask = host.WaitForAsyncResponseAsync(cancellationToken);

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        Task completedTask;
                        Task pollTask = Task.Delay(50, cancellationToken);

                        try
                        {
                            completedTask = await Task.WhenAny(readTask, asyncResponseTask, pollTask).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        if (completedTask != readTask)
                        {
                            await FlushReadyAsyncResponsesAsync(host, connection, cancellationToken).ConfigureAwait(false);

                            if (completedTask == asyncResponseTask)
                            {
                                asyncResponseTask = host.WaitForAsyncResponseAsync(cancellationToken);
                            }

                            continue;
                        }

                        byte[] requestPayload;

                        try
                        {
                            requestPayload = await readTask.ConfigureAwait(false);
                        }
                        catch (ChannelClosedException)
                        {
                            break;
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        byte[]? responsePayload;

                        lock (host.SyncRoot)
                        {
                            responsePayload = DispatchRequest(host, requestPayload);
                        }

                        if (responsePayload != null)
                        {
                            await connection.WriteAsync(responsePayload, cancellationToken).ConfigureAwait(false);
                        }

                        await FlushReadyAsyncResponsesAsync(host, connection, cancellationToken).ConfigureAwait(false);
                        readTask = connection.ReadAsync(cancellationToken).AsTask();
                        asyncResponseTask = host.WaitForAsyncResponseAsync(cancellationToken);
                    }
                }
                catch (IOException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
                catch (SocketException)
                {
                }
                catch (ProtocolEncodingException exception)
                {
                    _ExceptionHandler(exception);
                }
                catch (ProtocolValidationException exception)
                {
                    _ExceptionHandler(exception);
                }
                catch (Exception exception)
                {
                    _ExceptionHandler(exception);
                }
                finally
                {
                    lock (host.SyncRoot)
                    {
                        host.HandleTransportDisconnect();
                    }

                    host.UnregisterFromSharedState();

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
                }
            }
        }

        private static async Task FlushReadyAsyncResponsesAsync(OpenCifsServerHost host, FramedPipeConnection connection, CancellationToken cancellationToken)
        {
            while (host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? asyncResponse) && asyncResponse != null)
            {
                await connection.WriteAsync(
                    CreateSingleResponsePacket(host, asyncResponse.Header, asyncResponse.Payload),
                    cancellationToken).ConfigureAwait(false);
            }
        }

        private static byte[]? DispatchRequest(OpenCifsServerHost host, ReadOnlyMemory<byte> requestPayload)
        {
            if (LooksLikeSmb1Packet(requestPayload.Span))
            {
                return DispatchSmb1MultiProtocolNegotiate(host, requestPayload);
            }

            Smb2CompoundPacket requestPacket = Smb2CompoundPacket.ReadFrom(requestPayload);
            host.ValidateRequestPacket(requestPacket, requestPayload);

            if (requestPacket.Entries.Count == 1)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[0];
                Smb2Header requestHeader = requestEntry.Header;
                byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimRequestPayload(requestHeader.Command, requestEntry.Payload);

                if (requestHeader.Command == Smb2Command.Cancel)
                {
                    Smb2CancelRequest cancelRequest = Smb2CancelRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerCancelResult cancelResult = host.HandleCancel(requestHeader, cancelRequest);

                    if (!cancelResult.WasCancelled || cancelResult.TargetResponseHeader == null)
                    {
                        return null;
                    }

                    return CreateSingleResponsePacket(host, cancelResult.TargetResponseHeader, cancelResult.TargetResponsePayload);
                }

                if (requestHeader.Command == Smb2Command.ChangeNotify)
                {
                    Smb2ChangeNotifyRequest changeNotifyRequest = Smb2ChangeNotifyRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerAsyncResponse asyncResponse = host.HandleChangeNotify(requestHeader, changeNotifyRequest);
                    return CreateSingleResponsePacket(host, asyncResponse.Header, asyncResponse.Payload);
                }
            }

            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(requestPacket);
            return host.FinalizeResponsePacket(responsePacket);
        }

        private static byte[] DispatchSmb1MultiProtocolNegotiate(OpenCifsServerHost host, ReadOnlyMemory<byte> requestPayload)
        {
            Smb1NegotiateRequest smb1Request = Smb1NegotiateRequest.ReadFrom(requestPayload);

            if (!smb1Request.ContainsDialect(Smb1NegotiateRequest.Smb2002DialectString))
            {
                throw new ProtocolValidationException("The bounded SMB1 multi-protocol negotiate bridge requires the SMB 2.002 dialect string.", nameof(requestPayload));
            }

            Smb2NegotiateRequest bridgedRequest = new Smb2NegotiateRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled,
                ClientGuid = new Guid("00000000-0000-0000-0000-000000000001"),
                Dialects = new SmbDialect[]
                {
                    SmbDialect.Smb2002,
                    SmbDialect.Smb21
                }
            };

            Smb2Header syntheticHeader = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = Smb2Command.Negotiate,
                CreditRequest = 1,
                Flags = Smb2HeaderFlags.None,
                NextCommand = 0,
                MessageId = 0,
                ProcessId = CombineProcessId(smb1Request.Header),
                TreeId = 0,
                AsyncId = 0,
                SessionId = 0,
                Signature = new byte[16]
            };
            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(syntheticHeader, bridgedRequest.ToByteArray())
            }));
            return host.FinalizeResponsePacket(responsePacket);
        }

        private static byte[] CreateSingleResponsePacket(OpenCifsServerHost host, Smb2Header responseHeader, byte[] responsePayload)
        {
            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(responseHeader, responsePayload ?? Array.Empty<byte>())
            });

            return host.FinalizeResponsePacket(responsePacket);
        }

        private static bool LooksLikeSmb1Packet(ReadOnlySpan<byte> buffer)
        {
            return buffer.Length >= 4 &&
                buffer[0] == 0xFF &&
                buffer[1] == 0x53 &&
                buffer[2] == 0x4D &&
                buffer[3] == 0x42;
        }

        private static uint CombineProcessId(Smb1Header header)
        {
            return ((uint)header.ProcessIdHigh << 16) | header.ProcessIdLow;
        }

        private static IPAddress ResolveBindAddress(string bindAddress)
        {
            if (IPAddress.TryParse(bindAddress, out IPAddress? parsedAddress) && parsedAddress != null)
            {
                return parsedAddress;
            }

            IPAddress[] addresses = Dns.GetHostAddresses(bindAddress);

            for (int index = 0; index < addresses.Length; index++)
            {
                if (addresses[index].AddressFamily == AddressFamily.InterNetwork)
                {
                    return addresses[index];
                }
            }

            for (int index = 0; index < addresses.Length; index++)
            {
                if (addresses[index].AddressFamily == AddressFamily.InterNetworkV6)
                {
                    return addresses[index];
                }
            }

            throw new InvalidOperationException("The configured bind address could not be resolved to an IP endpoint.");
        }

        private readonly object _ConnectionSync = new object();
        private readonly List<Task> _ConnectionTasks = new List<Task>();
        private readonly Action<Exception> _ExceptionHandler;
        private readonly Func<OpenCifsServerHost> _HostFactory;
        private readonly OpenCifsServerOptions _Options;
        private bool _IsRunning;
    }
}

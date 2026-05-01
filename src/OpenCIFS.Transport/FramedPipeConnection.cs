namespace OpenCIFS.Transport
{
    using System;
    using System.Buffers;
    using System.IO;
    using System.IO.Pipelines;
    using System.Threading.Channels;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Pipe-based framed transport connection with explicit read and write loops.
    /// </summary>
    public sealed class FramedPipeConnection : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Initialize the framed connection.
        /// </summary>
        /// <param name="inboundReader">Inbound pipe reader.</param>
        /// <param name="outboundWriter">Outbound pipe writer.</param>
        /// <param name="frameProtocol">Frame protocol.</param>
        /// <param name="options">Connection options.</param>
        public FramedPipeConnection(PipeReader inboundReader, PipeWriter outboundWriter, IFrameProtocol frameProtocol, FramedPipeConnectionOptions? options = null)
        {
            _InboundReader = inboundReader ?? throw new ArgumentNullException(nameof(inboundReader));
            _OutboundWriter = outboundWriter ?? throw new ArgumentNullException(nameof(outboundWriter));
            _FrameProtocol = frameProtocol ?? throw new ArgumentNullException(nameof(frameProtocol));
            _Options = options ?? new FramedPipeConnectionOptions();
            _InboundFrames = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(_Options.InboundFrameCapacity) { SingleReader = false, SingleWriter = true });
            _OutboundFrames = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(_Options.OutboundFrameCapacity) { SingleReader = true, SingleWriter = false });
        }

        /// <summary>
        /// Create a framed connection over a full-duplex stream.
        /// </summary>
        /// <param name="stream">Full-duplex stream.</param>
        /// <param name="frameProtocol">Frame protocol.</param>
        /// <param name="options">Connection options.</param>
        /// <returns>Framed connection.</returns>
        public static FramedPipeConnection Create(Stream stream, IFrameProtocol frameProtocol, FramedPipeConnectionOptions? options = null)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            PipeReader inboundReader = PipeReader.Create(stream);
            PipeWriter outboundWriter = PipeWriter.Create(stream);
            return new FramedPipeConnection(inboundReader, outboundWriter, frameProtocol, options);
        }

        /// <summary>
        /// Completion task for the read and write loops.
        /// </summary>
        public Task Completion
        {
            get
            {
                return _Completion;
            }
        }

        /// <summary>
        /// Start the read and write loops.
        /// </summary>
        public void Start()
        {
            EnsureNotDisposed();

            if (_Started)
            {
                throw new InvalidOperationException("The framed connection has already been started.");
            }

            _Started = true;
            Task readLoop = ReadLoopAsync(_CancellationTokenSource.Token);
            Task writeLoop = WriteLoopAsync(_CancellationTokenSource.Token);
            _Completion = Task.WhenAll(readLoop, writeLoop);
        }

        /// <summary>
        /// Read the next inbound frame payload.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Frame payload bytes.</returns>
        public async ValueTask<byte[]> ReadAsync(CancellationToken cancellationToken = default)
        {
            EnsureReady();
            byte[] payload = await _InboundFrames.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            return payload;
        }

        /// <summary>
        /// Queue an outbound frame payload for transmission.
        /// </summary>
        /// <param name="payload">Payload bytes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
        {
            EnsureReady();

            if (payload.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(payload), "Outbound frame payloads must not be empty.");
            }

            await _OutboundFrames.Writer.WriteAsync(payload.ToArray(), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Mark the outbound frame queue as complete.
        /// </summary>
        public void CompleteWrites()
        {
            EnsureReady();
            _OutboundFrames.Writer.TryComplete();
        }

        /// <summary>
        /// Dispose the connection and wait for loop shutdown.
        /// </summary>
        public void Dispose()
        {
            if (_Disposed)
            {
                return;
            }

            _Disposed = true;
            _CancellationTokenSource.Cancel();
            _OutboundFrames.Writer.TryComplete();

            if (_Started)
            {
                _Completion.GetAwaiter().GetResult();
            }

            _CancellationTokenSource.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose the connection and wait asynchronously for loop shutdown.
        /// </summary>
        /// <returns>Completion task.</returns>
        public async ValueTask DisposeAsync()
        {
            if (_Disposed)
            {
                return;
            }

            _Disposed = true;
            _CancellationTokenSource.Cancel();
            _OutboundFrames.Writer.TryComplete();

            if (_Started)
            {
                await _Completion.ConfigureAwait(false);
            }

            _CancellationTokenSource.Dispose();
            GC.SuppressFinalize(this);
        }

        private void EnsureReady()
        {
            EnsureNotDisposed();

            if (!_Started)
            {
                throw new InvalidOperationException("The framed connection must be started before use.");
            }
        }

        private void EnsureNotDisposed()
        {
            if (_Disposed)
            {
                throw new ObjectDisposedException(nameof(FramedPipeConnection), "The framed connection has been disposed.");
            }
        }

        private async Task ReadLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (true)
                {
                    ReadResult readResult = await _InboundReader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    ReadOnlySequence<byte> buffer = readResult.Buffer;
                    long consumedBytes = 0;

                    while (_FrameProtocol.TryReadFrame(buffer.Slice(consumedBytes), out byte[]? payload, out long bytesRead))
                    {
                        if (payload == null)
                        {
                            throw new ProtocolValidationException("The frame protocol returned a null payload.");
                        }

                        consumedBytes += bytesRead;
                        await _InboundFrames.Writer.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                    }

                    SequencePosition consumedPosition = buffer.GetPosition(consumedBytes);
                    _InboundReader.AdvanceTo(consumedPosition, buffer.End);

                    if (readResult.IsCompleted)
                    {
                        if (buffer.Length != consumedBytes)
                        {
                            throw new ProtocolValidationException("The inbound transport ended with an incomplete frame.");
                        }

                        break;
                    }
                }

                _InboundFrames.Writer.TryComplete();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _InboundFrames.Writer.TryComplete();
            }
            catch (IOException) when (cancellationToken.IsCancellationRequested)
            {
                _InboundFrames.Writer.TryComplete();
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
                _InboundFrames.Writer.TryComplete();
            }
            catch (Exception exception)
            {
                _InboundFrames.Writer.TryComplete(exception);
                throw;
            }
            finally
            {
                try
                {
                    await _InboundReader.CompleteAsync().ConfigureAwait(false);
                }
                catch (IOException) when (cancellationToken.IsCancellationRequested)
                {
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                }
            }
        }

        private async Task WriteLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (await _OutboundFrames.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (_OutboundFrames.Reader.TryRead(out byte[]? payload))
                    {
                        if (payload == null)
                        {
                            throw new ProtocolValidationException("The outbound frame queue produced a null payload.");
                        }

                        await _FrameProtocol.WriteFrameAsync(_OutboundWriter, payload, cancellationToken).ConfigureAwait(false);
                        await _OutboundWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                try
                {
                    await _OutboundWriter.CompleteAsync().ConfigureAwait(false);
                }
                catch (IOException) when (cancellationToken.IsCancellationRequested)
                {
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                }
            }
        }

        private readonly PipeReader _InboundReader;
        private readonly PipeWriter _OutboundWriter;
        private readonly IFrameProtocol _FrameProtocol;
        private readonly FramedPipeConnectionOptions _Options;
        private readonly Channel<byte[]> _InboundFrames;
        private readonly Channel<byte[]> _OutboundFrames;
        private readonly CancellationTokenSource _CancellationTokenSource = new CancellationTokenSource();
        private Task _Completion = Task.CompletedTask;
        private bool _Started = false;
        private bool _Disposed = false;
    }
}

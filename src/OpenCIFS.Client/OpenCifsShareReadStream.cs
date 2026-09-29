namespace OpenCIFS.Client
{
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Read-only, seekable stream over an open SMB file handle returned by <see cref="OpenCifsShareFileOperations.OpenReadAsync"/>.
    /// </summary>
    internal sealed class OpenCifsShareReadStream : Stream
    {
        internal OpenCifsShareReadStream(OpenCifsShareSession shareSession, OpenCifsClientOpenHandle openHandle, long length, int maximumChunkLength)
        {
            _ShareSession = shareSession ?? throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
            _OpenHandle = openHandle ?? throw new ArgumentNullException(nameof(openHandle), "OpenHandle cannot be null.");

            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than or equal to zero.");
            }

            if (maximumChunkLength < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumChunkLength), "MaximumChunkLength must be greater than zero.");
            }

            _Length = length;
            _MaximumChunkLength = maximumChunkLength;
        }

        /// <inheritdoc />
        public override bool CanRead
        {
            get
            {
                return !IsDisposed;
            }
        }

        /// <inheritdoc />
        public override bool CanSeek
        {
            get
            {
                return !IsDisposed;
            }
        }

        /// <inheritdoc />
        public override bool CanWrite
        {
            get
            {
                return false;
            }
        }

        /// <inheritdoc />
        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                return _Length;
            }
        }

        /// <inheritdoc />
        public override long Position
        {
            get
            {
                ThrowIfDisposed();
                return _Position;
            }
            set
            {
                ThrowIfDisposed();

                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "Position must be greater than or equal to zero.");
                }

                _Position = value;
            }
        }

        /// <inheritdoc />
        public override void Flush()
        {
        }

        /// <inheritdoc />
        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return cancellationToken.IsCancellationRequested ? Task.FromCanceled(cancellationToken) : Task.CompletedTask;
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            return ReadCoreAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();
        }

        /// <inheritdoc />
        public override int Read(Span<byte> buffer)
        {
            byte[] temporary = new byte[buffer.Length];
            int read = ReadCoreAsync(temporary, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            temporary.AsSpan(0, read).CopyTo(buffer);
            return read;
        }

        /// <inheritdoc />
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return ReadCoreAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return ReadCoreAsync(buffer, cancellationToken);
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();
            long basePosition = origin switch
            {
                SeekOrigin.Begin => 0,
                SeekOrigin.Current => _Position,
                SeekOrigin.End => _Length,
                _ => throw new ArgumentException("Origin is not a valid SeekOrigin value.", nameof(origin))
            };
            long newPosition = basePosition + offset;

            if (newPosition < 0)
            {
                throw new IOException("An attempt was made to move the position before the beginning of the stream.");
            }

            _Position = newPosition;
            return _Position;
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            throw new NotSupportedException("The OpenCIFS read stream does not support SetLength.");
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("The OpenCIFS read stream does not support writing.");
        }

        /// <inheritdoc />
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            throw new NotSupportedException("The OpenCIFS read stream does not support writing.");
        }

        /// <inheritdoc />
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            throw new NotSupportedException("The OpenCIFS read stream does not support writing.");
        }

        /// <inheritdoc />
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("The OpenCIFS read stream does not support writing.");
        }

        /// <inheritdoc />
        public override async ValueTask DisposeAsync()
        {
            if (!TryMarkDisposed())
            {
                return;
            }

            await _ShareSession.TryCloseOpenAsync(_OpenHandle).ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing && TryMarkDisposed())
            {
                try
                {
                    _ShareSession.TryCloseOpenAsync(_OpenHandle).GetAwaiter().GetResult();
                }
                catch
                {
                }
            }

            base.Dispose(disposing);
        }

        private async ValueTask<int> ReadCoreAsync(Memory<byte> destination, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            if (destination.Length == 0 || _Position >= _Length)
            {
                return 0;
            }

            int requestLength = (int)Math.Min(Math.Min(destination.Length, _MaximumChunkLength), _Length - _Position);
            OpenCifsClientConnection connection = _ShareSession.Connection;
            byte[] chunk = await connection.ReadAsync(
                _OpenHandle,
                (uint)requestLength,
                (ulong)_Position,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // A zero-length read means the file shrank after the stream was opened; report end-of-stream.
            int copyCount = Math.Min(chunk.Length, requestLength);
            chunk.AsSpan(0, copyCount).CopyTo(destination.Span);
            _Position += copyCount;
            return copyCount;
        }

        private bool TryMarkDisposed()
        {
            return Interlocked.Exchange(ref _DisposeState, 1) == 0;
        }

        private void ThrowIfDisposed()
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException(nameof(OpenCifsShareReadStream), "The OpenCIFS read stream has been disposed.");
            }
        }

        private bool IsDisposed
        {
            get
            {
                return Volatile.Read(ref _DisposeState) != 0;
            }
        }

        private readonly OpenCifsShareSession _ShareSession;
        private readonly OpenCifsClientOpenHandle _OpenHandle;
        private readonly long _Length;
        private readonly int _MaximumChunkLength;
        private long _Position;
        private int _DisposeState;
    }
}

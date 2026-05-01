namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Disposable byte-range lock handle returned by the share-scoped locking surface.
    /// </summary>
    public sealed class OpenCifsShareFileLock : IDisposable, IAsyncDisposable
    {
        internal OpenCifsShareFileLock(
            OpenCifsClientConnection connection,
            OpenCifsClientOpenHandle openHandle,
            OpenCifsClientTreeHandle? transientTreeHandle,
            string path,
            ulong offset,
            ulong length,
            bool isShared)
        {
            _Connection = connection ?? throw new ArgumentNullException(nameof(connection), "Connection cannot be null.");
            _OpenHandle = openHandle ?? throw new ArgumentNullException(nameof(openHandle), "OpenHandle cannot be null.");
            _TransientTreeHandle = transientTreeHandle;
            Path = string.IsNullOrWhiteSpace(path) ? throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.") : path;
            Offset = offset;
            Length = length;
            IsShared = isShared;
        }

        /// <summary>
        /// Locked relative file path.
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// Locked byte offset.
        /// </summary>
        public ulong Offset { get; }

        /// <summary>
        /// Locked byte length.
        /// </summary>
        public ulong Length { get; }

        /// <summary>
        /// Whether the lock is shared.
        /// </summary>
        public bool IsShared { get; }

        /// <summary>
        /// Whether the lock has been released.
        /// </summary>
        public bool IsReleased { get; private set; }

        /// <summary>
        /// Release the lock and close the backing open.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task ReleaseAsync(CancellationToken cancellationToken = default)
        {
            if (IsReleased)
            {
                return;
            }

            IsReleased = true;

            try
            {
                await _Connection.LockAsync(_OpenHandle, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = Offset,
                        Length = Length,
                        Flags = Smb2LockFlags.Unlock
                    }
                }, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    await _Connection.CloseAsync(_OpenHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                }

                if (_TransientTreeHandle != null && !_TransientTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await _Connection.TreeDisconnectAsync(_TransientTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (IsReleased)
            {
                return;
            }

            ReleaseAsync(CancellationToken.None).GetAwaiter().GetResult();
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            await ReleaseAsync(CancellationToken.None).ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }

        private readonly OpenCifsClientConnection _Connection;
        private readonly OpenCifsClientOpenHandle _OpenHandle;
        private readonly OpenCifsClientTreeHandle? _TransientTreeHandle;
    }
}

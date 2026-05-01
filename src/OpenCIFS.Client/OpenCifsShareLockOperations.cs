namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Grouped share-scoped locking operations.
    /// </summary>
    public sealed class OpenCifsShareLockOperations
    {
        private const uint DefaultDesiredAccess = 0xC0000000U;

        internal OpenCifsShareLockOperations(OpenCifsShareSession shareSession)
        {
            _ShareSession = shareSession ?? throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
        }

        /// <summary>
        /// Acquire an exclusive byte-range lock and keep it alive until the returned lock handle is released.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Byte offset where the range starts.</param>
        /// <param name="length">Byte length of the range.</param>
        /// <param name="failImmediately">Whether the lock should fail immediately instead of waiting.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Disposable file lock handle.</returns>
        public Task<OpenCifsShareFileLock> AcquireExclusiveAsync(
            string path,
            ulong offset,
            ulong length,
            bool failImmediately = true,
            CancellationToken cancellationToken = default)
        {
            return AcquireAsync(path, offset, length, shared: false, failImmediately, cancellationToken);
        }

        /// <summary>
        /// Acquire an exclusive byte-range lock without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Byte offset where the range starts.</param>
        /// <param name="length">Byte length of the range.</param>
        /// <param name="failImmediately">Whether the lock should fail immediately instead of waiting.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsShareFileLock>> TryAcquireExclusiveAsync(
            string path,
            ulong offset,
            ulong length,
            bool failImmediately = true,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => AcquireExclusiveAsync(path, offset, length, failImmediately, cancellationToken));
        }

        /// <summary>
        /// Acquire a shared byte-range lock and keep it alive until the returned lock handle is released.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Byte offset where the range starts.</param>
        /// <param name="length">Byte length of the range.</param>
        /// <param name="failImmediately">Whether the lock should fail immediately instead of waiting.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Disposable file lock handle.</returns>
        public Task<OpenCifsShareFileLock> AcquireSharedAsync(
            string path,
            ulong offset,
            ulong length,
            bool failImmediately = true,
            CancellationToken cancellationToken = default)
        {
            return AcquireAsync(path, offset, length, shared: true, failImmediately, cancellationToken);
        }

        /// <summary>
        /// Acquire a shared byte-range lock without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Byte offset where the range starts.</param>
        /// <param name="length">Byte length of the range.</param>
        /// <param name="failImmediately">Whether the lock should fail immediately instead of waiting.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsShareFileLock>> TryAcquireSharedAsync(
            string path,
            ulong offset,
            ulong length,
            bool failImmediately = true,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => AcquireSharedAsync(path, offset, length, failImmediately, cancellationToken));
        }

        private async Task<OpenCifsShareFileLock> AcquireAsync(
            string path,
            ulong offset,
            ulong length,
            bool shared,
            bool failImmediately,
            CancellationToken cancellationToken)
        {
            if (length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            try
            {
                return await AcquireCoreAsync(_ShareSession.Connection, _ShareSession.GetTreeHandle(), path, offset, length, shared, failImmediately, null, cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.PathNotCovered)
            {
                OpenCifsResolvedDfsPath resolvedPath = await _ShareSession.ResolvePathAsync(path, cancellationToken).ConfigureAwait(false);

                if (!resolvedPath.IsSameServer)
                {
                    throw new OpenCifsClientStateException("The bounded managed DFS locking path only supports same-server referral targets.");
                }

                OpenCifsClientTreeHandle? transientTreeHandle = null;
                OpenCifsClientTreeHandle targetTreeHandle = _ShareSession.GetTreeHandle();

                if (!string.Equals(resolvedPath.TargetShareName, _ShareSession.ShareName, StringComparison.OrdinalIgnoreCase))
                {
                    transientTreeHandle = await _ShareSession.Connection.TreeConnectAsync(resolvedPath.TargetShareName, cancellationToken).ConfigureAwait(false);
                    targetTreeHandle = transientTreeHandle;
                }

                try
                {
                    return await AcquireCoreAsync(
                        _ShareSession.Connection,
                        targetTreeHandle,
                        resolvedPath.TargetRelativePath,
                        offset,
                        length,
                        shared,
                        failImmediately,
                        transientTreeHandle,
                        cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    if (transientTreeHandle != null && !transientTreeHandle.IsDisconnected)
                    {
                        try
                        {
                            await _ShareSession.Connection.TreeDisconnectAsync(transientTreeHandle, CancellationToken.None).ConfigureAwait(false);
                        }
                        catch
                        {
                        }
                    }

                    throw;
                }
            }
        }

        private async Task<OpenCifsShareFileLock> AcquireCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            ulong offset,
            ulong length,
            bool shared,
            bool failImmediately,
            OpenCifsClientTreeHandle? transientTreeHandle,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                DefaultDesiredAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                Smb2LockFlags flags = shared ? Smb2LockFlags.SharedLock : Smb2LockFlags.ExclusiveLock;

                if (failImmediately)
                {
                    flags |= Smb2LockFlags.FailImmediately;
                }

                await connection.LockAsync(openHandle, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = offset,
                        Length = length,
                        Flags = flags
                    }
                }, cancellationToken).ConfigureAwait(false);

                return new OpenCifsShareFileLock(connection, openHandle, transientTreeHandle, path, offset, length, shared);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);

                if (transientTreeHandle != null && !transientTreeHandle.IsDisconnected)
                {
                    try
                    {
                        await connection.TreeDisconnectAsync(transientTreeHandle, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }

                throw;
            }
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}

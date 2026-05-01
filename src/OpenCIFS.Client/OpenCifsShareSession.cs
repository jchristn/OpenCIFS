namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Share-scoped primary work session for grouped path-first operations.
    /// </summary>
    public sealed class OpenCifsShareSession : IAsyncDisposable
    {
        internal OpenCifsShareSession(OpenCifsClient client, OpenCifsClientTreeHandle treeHandle)
        {
            _Client = client ?? throw new ArgumentNullException(nameof(client), "Client cannot be null.");
            TreeHandle = treeHandle ?? throw new ArgumentNullException(nameof(treeHandle), "TreeHandle cannot be null.");
            Files = new OpenCifsShareFileOperations(this);
            Directories = new OpenCifsShareDirectoryOperations(this);
            Metadata = new OpenCifsShareMetadataOperations(this);
            Locks = new OpenCifsShareLockOperations(this);
        }

        /// <summary>
        /// Share name for the open tree.
        /// </summary>
        public string ShareName
        {
            get
            {
                return TreeHandle.ShareName;
            }
        }

        /// <summary>
        /// Grouped file operations.
        /// </summary>
        public OpenCifsShareFileOperations Files { get; }

        /// <summary>
        /// Grouped directory operations.
        /// </summary>
        public OpenCifsShareDirectoryOperations Directories { get; }

        /// <summary>
        /// Grouped metadata operations.
        /// </summary>
        public OpenCifsShareMetadataOperations Metadata { get; }

        /// <summary>
        /// Grouped locking operations.
        /// </summary>
        public OpenCifsShareLockOperations Locks { get; }

        /// <summary>
        /// Query bounded DFS referrals for a share-relative DFS namespace path through the current OpenCIFS session.
        /// </summary>
        /// <param name="path">Share-relative DFS path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Returned DFS referral entries.</returns>
        public Task<OpenCifsDfsReferral[]> GetDfsReferralsAsync(string path, CancellationToken cancellationToken = default)
        {
            EnsureActive();
            return Connection.GetDfsReferralsAsync(BuildDfsPath(path), cancellationToken);
        }

        /// <summary>
        /// Query bounded DFS referrals for a share-relative path without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Share-relative DFS path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsDfsReferral[]>> TryGetDfsReferralsAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => GetDfsReferralsAsync(path, cancellationToken));
        }

        /// <summary>
        /// Resolve a share-relative DFS namespace path to a concrete target UNC path, using a referral cache when possible.
        /// </summary>
        /// <param name="path">Share-relative DFS path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Resolved DFS target path.</returns>
        public Task<OpenCifsResolvedDfsPath> ResolvePathAsync(string path, CancellationToken cancellationToken = default)
        {
            EnsureActive();
            return Connection.ResolveDfsPathAsync(BuildDfsPath(path), cancellationToken);
        }

        /// <summary>
        /// Resolve a share-relative DFS path without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Share-relative DFS path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsResolvedDfsPath>> TryResolvePathAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ResolvePathAsync(path, cancellationToken));
        }

        /// <summary>
        /// Advanced/raw direct-TCP connection surface for protocol-exact workflows.
        /// </summary>
        public OpenCifsClientConnection AdvancedConnection
        {
            get
            {
                EnsureActive();
                return _Client.AdvancedConnection;
            }
        }

        /// <summary>
        /// Advanced/raw tree handle for protocol-exact workflows.
        /// </summary>
        public OpenCifsClientTreeHandle AdvancedTreeHandle
        {
            get
            {
                EnsureActive();
                return TreeHandle;
            }
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            if (_Closed)
            {
                return;
            }

            _Closed = true;
            await _Client.CloseShareSessionAsync(this, CancellationToken.None).ConfigureAwait(false);
        }

        internal OpenCifsClientConnection Connection
        {
            get
            {
                EnsureActive();
                return _Client.Connection;
            }
        }

        internal OpenCifsClientTreeHandle TreeHandle { get; }

        internal OpenCifsClientTreeHandle GetTreeHandle()
        {
            EnsureActive();
            return TreeHandle;
        }

        internal async Task<T> ExecuteSinglePathAsync<T>(
            string path,
            CancellationToken cancellationToken,
            Func<OpenCifsClientConnection, OpenCifsClientTreeHandle, string, CancellationToken, Task<T>> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation), "Operation cannot be null.");
            }

            EnsureActive();

            try
            {
                return await operation(Connection, GetTreeHandle(), path, cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.PathNotCovered)
            {
                OpenCifsResolvedDfsPath resolvedPath = await ResolvePathAsync(path, cancellationToken).ConfigureAwait(false);
                return await ExecuteResolvedSinglePathAsync(resolvedPath, cancellationToken, operation).ConfigureAwait(false);
            }
        }

        internal async Task ExecuteSinglePathAsync(
            string path,
            CancellationToken cancellationToken,
            Func<OpenCifsClientConnection, OpenCifsClientTreeHandle, string, CancellationToken, Task> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation), "Operation cannot be null.");
            }

            await ExecuteSinglePathAsync<object?>(
                path,
                cancellationToken,
                async (connection, treeHandle, resolvedPath, token) =>
                {
                    await operation(connection, treeHandle, resolvedPath, token).ConfigureAwait(false);
                    return null;
                }).ConfigureAwait(false);
        }

        internal async Task ExecuteDualPathAsync(
            string sourcePath,
            string destinationPath,
            CancellationToken cancellationToken,
            Func<OpenCifsClientConnection, OpenCifsClientTreeHandle, string, string, CancellationToken, Task> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation), "Operation cannot be null.");
            }

            EnsureActive();

            try
            {
                await operation(Connection, GetTreeHandle(), sourcePath, destinationPath, cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.PathNotCovered)
            {
                OpenCifsResolvedDfsPath resolvedSourcePath = await ResolvePathAsync(sourcePath, cancellationToken).ConfigureAwait(false);
                OpenCifsResolvedDfsPath resolvedDestinationPath = await ResolvePathAsync(destinationPath, cancellationToken).ConfigureAwait(false);

                if (!resolvedSourcePath.IsSameServer || !resolvedDestinationPath.IsSameServer)
                {
                    throw new OpenCifsClientStateException("The bounded managed DFS rename path only supports same-server referral targets.");
                }

                if (!string.Equals(resolvedSourcePath.TargetShareName, resolvedDestinationPath.TargetShareName, StringComparison.OrdinalIgnoreCase))
                {
                    throw new OpenCifsClientStateException("The bounded managed DFS rename path only supports source and destination referral targets on the same share.");
                }

                (OpenCifsClientTreeHandle treeHandle, bool ownsTree) = await AcquireResolvedTreeAsync(resolvedSourcePath, cancellationToken).ConfigureAwait(false);

                try
                {
                    await operation(
                        Connection,
                        treeHandle,
                        resolvedSourcePath.TargetRelativePath,
                        resolvedDestinationPath.TargetRelativePath,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    await TryDisconnectResolvedTreeAsync(treeHandle, ownsTree).ConfigureAwait(false);
                }
            }
        }

        internal void EnsureActive()
        {
            if (_Closed)
            {
                throw new OpenCifsClientStateException("The share session has already been closed.");
            }

            if (!_Client.IsConnected || !_Client.IsAuthenticated)
            {
                throw new OpenCifsClientStateException("The parent client must remain connected and authenticated while using a share session.");
            }
        }

        internal async Task TryCloseOpenAsync(OpenCifsClientOpenHandle openHandle)
        {
            try
            {
                await _Client.Connection.CloseAsync(openHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        internal void MarkClosed()
        {
            _Closed = true;
        }

        private string BuildDfsPath(string path)
        {
            string normalizedPath = string.IsNullOrWhiteSpace(path)
                ? string.Empty
                : path.Trim().Replace('/', '\\').Trim('\\');
            string serverName = Connection.Options.ServerName.Trim().Trim('\\');
            return normalizedPath.Length == 0
                ? "\\" + serverName + "\\" + ShareName
                : "\\" + serverName + "\\" + ShareName + "\\" + normalizedPath;
        }

        private async Task<T> ExecuteResolvedSinglePathAsync<T>(
            OpenCifsResolvedDfsPath resolvedPath,
            CancellationToken cancellationToken,
            Func<OpenCifsClientConnection, OpenCifsClientTreeHandle, string, CancellationToken, Task<T>> operation)
        {
            if (!resolvedPath.IsSameServer)
            {
                throw new OpenCifsClientStateException("The bounded managed DFS path resolver only supports same-server referral targets for share-session operations.");
            }

            (OpenCifsClientTreeHandle treeHandle, bool ownsTree) = await AcquireResolvedTreeAsync(resolvedPath, cancellationToken).ConfigureAwait(false);

            try
            {
                return await operation(Connection, treeHandle, resolvedPath.TargetRelativePath, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await TryDisconnectResolvedTreeAsync(treeHandle, ownsTree).ConfigureAwait(false);
            }
        }

        private async Task<(OpenCifsClientTreeHandle TreeHandle, bool OwnsTree)> AcquireResolvedTreeAsync(OpenCifsResolvedDfsPath resolvedPath, CancellationToken cancellationToken)
        {
            if (string.Equals(resolvedPath.TargetShareName, ShareName, StringComparison.OrdinalIgnoreCase))
            {
                return (GetTreeHandle(), false);
            }

            OpenCifsClientTreeHandle treeHandle = await Connection.TreeConnectAsync(resolvedPath.TargetShareName, cancellationToken).ConfigureAwait(false);
            return (treeHandle, true);
        }

        private async Task TryDisconnectResolvedTreeAsync(OpenCifsClientTreeHandle treeHandle, bool ownsTree)
        {
            if (!ownsTree || treeHandle.IsDisconnected)
            {
                return;
            }

            try
            {
                await Connection.TreeDisconnectAsync(treeHandle, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private readonly OpenCifsClient _Client;
        private bool _Closed;
    }
}


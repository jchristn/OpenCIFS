namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Grouped share-scoped directory operations.
    /// </summary>
    public sealed class OpenCifsShareDirectoryOperations
    {
        private const uint DefaultDirectoryQueryBufferLength = 4096;
        private const uint DefaultChangeNotifyBufferLength = 4096;
        private const uint GenericReadAccess = 0x80000000U;
        private const uint DeleteAccessMask = 0x00010000U;

        internal OpenCifsShareDirectoryOperations(OpenCifsShareSession shareSession)
        {
            _ShareSession = shareSession ?? throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
        }

        /// <summary>
        /// Create a directory if it does not already exist.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task CreateAsync(string path, CancellationToken cancellationToken = default)
        {
            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => CreateCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Create a directory without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryCreateAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CreateAsync(path, cancellationToken));
        }

        /// <summary>
        /// Enumerate a directory through FILE_FULL_DIRECTORY_INFORMATION responses.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded directory entries.</returns>
        public async Task<OpenCifsClientDirectoryEntry[]> EnumerateAsync(string path, string? fileNamePattern = null, CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => EnumerateCoreAsync(connection, treeHandle, resolvedPath, fileNamePattern, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Enumerate a directory without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientDirectoryEntry[]>> TryEnumerateAsync(string path, string? fileNamePattern = null, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => EnumerateAsync(path, fileNamePattern, cancellationToken));
        }

        /// <summary>
        /// Delete an existing empty directory.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task DeleteAsync(string path, CancellationToken cancellationToken = default)
        {
            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => DeleteCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Delete an existing empty directory without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryDeleteAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => DeleteAsync(path, cancellationToken));
        }

        /// <summary>
        /// Rename an existing directory within the share.
        /// </summary>
        /// <param name="path">Existing relative directory path.</param>
        /// <param name="newPath">New relative directory path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task RenameAsync(string path, string newPath, bool replaceIfExists = false, CancellationToken cancellationToken = default)
        {
            await _ShareSession.ExecuteDualPathAsync(
                path,
                newPath,
                cancellationToken,
                (connection, treeHandle, resolvedPath, resolvedNewPath, token) => RenameCoreAsync(connection, treeHandle, resolvedPath, resolvedNewPath, replaceIfExists, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Rename an existing directory within the share without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Existing relative directory path.</param>
        /// <param name="newPath">New relative directory path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryRenameAsync(string path, string newPath, bool replaceIfExists = false, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => RenameAsync(path, newPath, replaceIfExists, cancellationToken));
        }

        /// <summary>
        /// Wait for a bounded directory change-notify completion.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="completionFilter">Requested completion filter.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the directory.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded change-notify entries.</returns>
        public async Task<OpenCifsClientChangeNotification[]> WaitForChangeAsync(
            string path,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => WaitForChangeCoreAsync(connection, treeHandle, resolvedPath, completionFilter, watchTree, token)).ConfigureAwait(false);
        }

        private async Task CreateCoreAsync(OpenCifsClientConnection connection, OpenCifsClientTreeHandle treeHandle, string path, CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.OpenIf,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task<OpenCifsClientDirectoryEntry[]> EnumerateCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            string? fileNamePattern,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                byte[] outputBuffer = await connection.QueryDirectoryAsync(
                    openHandle,
                    FileInformationClass.FullDirectoryInformation,
                    outputBufferLength: DefaultDirectoryQueryBufferLength,
                    fileNamePattern: fileNamePattern,
                    flags: Smb2QueryDirectoryFlags.RestartScans,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                FileFullDirectoryInformationEntry[] entries = FileFullDirectoryInformationEntry.DecodeEntries(outputBuffer);
                OpenCifsClientDirectoryEntry[] results = new OpenCifsClientDirectoryEntry[entries.Length];

                for (int index = 0; index < entries.Length; index++)
                {
                    results[index] = new OpenCifsClientDirectoryEntry
                    {
                        FileName = entries[index].FileName,
                        EndOfFile = entries[index].EndOfFile,
                        AllocationSize = entries[index].AllocationSize,
                        FileAttributes = entries[index].FileAttributes
                    };
                }

                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return results;
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task DeleteCoreAsync(OpenCifsClientConnection connection, OpenCifsClientTreeHandle treeHandle, string path, CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                DeleteAccessMask,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await connection.SetDeletePendingAsync(openHandle, deletePending: true, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task RenameCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            string newPath,
            bool replaceIfExists,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericReadAccess | DeleteAccessMask,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await connection.SetRenameAsync(openHandle, newPath, replaceIfExists, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task<OpenCifsClientChangeNotification[]> WaitForChangeCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            FileNotifyChangeFilter completionFilter,
            bool watchTree,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                FileNotifyInformation[] entries = await connection.ChangeNotifyAsync(
                    openHandle,
                    completionFilter,
                    watchTree,
                    DefaultChangeNotifyBufferLength,
                    cancellationToken).ConfigureAwait(false);
                OpenCifsClientChangeNotification[] results = new OpenCifsClientChangeNotification[entries.Length];

                for (int index = 0; index < entries.Length; index++)
                {
                    results[index] = new OpenCifsClientChangeNotification
                    {
                        Action = entries[index].Action,
                        FileName = entries[index].FileName
                    };
                }

                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return results;
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Wait for a bounded directory change-notify completion without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="completionFilter">Requested completion filter.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the directory.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientChangeNotification[]>> TryWaitForChangeAsync(
            string path,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WaitForChangeAsync(path, completionFilter, watchTree, cancellationToken));
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}

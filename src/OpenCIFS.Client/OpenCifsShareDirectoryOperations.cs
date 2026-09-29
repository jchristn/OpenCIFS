namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Grouped share-scoped directory operations.
    /// </summary>
    public sealed class OpenCifsShareDirectoryOperations
    {
        private const uint DefaultDirectoryQueryBufferLength = 4096;
        private const uint MaximumDirectoryQueryBufferLength = 65536;
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
        /// Create a directory if it does not already exist, optionally creating every missing ancestor first.
        /// </summary>
        /// <remarks>
        /// When <paramref name="createParents"/> is true the call is idempotent across the whole path: ancestors and
        /// the target that already exist as directories are left unchanged. An ancestor that exists as a file fails
        /// with the server status (for example <c>STATUS_NOT_A_DIRECTORY</c> or <c>STATUS_OBJECT_NAME_COLLISION</c>).
        /// When <paramref name="createParents"/> is false this behaves exactly like <see cref="CreateAsync(string, CancellationToken)"/>.
        /// </remarks>
        /// <param name="path">Relative directory path.</param>
        /// <param name="createParents">Whether missing ancestor directories are created.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task CreateAsync(string path, bool createParents, CancellationToken cancellationToken = default)
        {
            if (!createParents)
            {
                await CreateAsync(path, cancellationToken).ConfigureAwait(false);
                return;
            }

            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => CreateWithParentsCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Create a directory, optionally including missing ancestors, without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative directory path.</param>
        /// <param name="createParents">Whether missing ancestor directories are created.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryCreateAsync(string path, bool createParents, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => CreateAsync(path, createParents, cancellationToken));
        }

        /// <summary>
        /// Enumerate a directory through FILE_FULL_DIRECTORY_INFORMATION responses.
        /// </summary>
        /// <remarks>
        /// Issues as many QUERY_DIRECTORY requests as needed (the first with SMB2_RESTART_SCANS) until the server
        /// reports the end of the scan, so arbitrarily large directories are returned completely. The <c>.</c> and
        /// <c>..</c> pseudo-entries are never included in the results.
        /// </remarks>
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
        /// <remarks>
        /// The wait holds the parent client's connection until a change arrives or the token is cancelled, so other
        /// operations on the same <see cref="OpenCifsClient"/> queue behind it. Use a dedicated client for notification waits.
        /// </remarks>
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
            OpenCifsClientOpenHandle openHandle;

            try
            {
                openHandle = await connection.OpenAsync(
                    treeHandle,
                    path,
                    desiredAccess: GenericReadAccess,
                    createDisposition: Smb2CreateDisposition.OpenIf,
                    createOptions: Smb2CreateOptions.DirectoryFile,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.ObjectNameNotFound)
            {
                openHandle = await connection.OpenAsync(
                    treeHandle,
                    path,
                    desiredAccess: GenericReadAccess,
                    fileAttributes: FileAttributes.Directory,
                    createDisposition: Smb2CreateDisposition.OpenIf,
                    createOptions: Smb2CreateOptions.None,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

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

        private async Task CreateWithParentsCoreAsync(OpenCifsClientConnection connection, OpenCifsClientTreeHandle treeHandle, string path, CancellationToken cancellationToken)
        {
            string[] segments = (path ?? string.Empty).Split(_PathSeparators, StringSplitOptions.RemoveEmptyEntries);

            if (segments.Length == 0)
            {
                // The share root always exists; open it exactly as the non-recursive overload would.
                await CreateCoreAsync(connection, treeHandle, path ?? string.Empty, cancellationToken).ConfigureAwait(false);
                return;
            }

            try
            {
                // Common case: every ancestor already exists, so one create round trip is enough.
                await CreateCoreAsync(connection, treeHandle, string.Join("\\", segments), cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.ObjectPathNotFound || exception.Status == NtStatus.ObjectNameNotFound)
            {
            }

            for (int index = 1; index <= segments.Length; index++)
            {
                await CreateCoreAsync(connection, treeHandle, string.Join("\\", segments, 0, index), cancellationToken).ConfigureAwait(false);
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
                uint outputBufferLength = GetDirectoryQueryBufferLength(connection);
                Smb2QueryDirectoryFlags flags = Smb2QueryDirectoryFlags.RestartScans;
                List<OpenCifsClientDirectoryEntry> results = new List<OpenCifsClientDirectoryEntry>();

                // A single QUERY_DIRECTORY response only carries as many entries as fit in the output buffer.
                // Keep issuing continuation queries on the same open until the server reports that the scan is
                // exhausted (STATUS_NO_MORE_FILES, or STATUS_NO_SUCH_FILE when the pattern never matched).
                while (true)
                {
                    byte[] outputBuffer;

                    try
                    {
                        outputBuffer = await connection.QueryDirectoryAsync(
                            openHandle,
                            FileInformationClass.FullDirectoryInformation,
                            outputBufferLength: outputBufferLength,
                            fileNamePattern: fileNamePattern,
                            flags: flags,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                    }
                    catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.NoMoreFiles || exception.Status == NtStatus.NoSuchFile)
                    {
                        break;
                    }

                    if (outputBuffer.Length == 0)
                    {
                        break;
                    }

                    FileFullDirectoryInformationEntry[] entries = FileFullDirectoryInformationEntry.DecodeEntries(outputBuffer);

                    if (entries.Length == 0)
                    {
                        break;
                    }

                    for (int index = 0; index < entries.Length; index++)
                    {
                        FileFullDirectoryInformationEntry entry = entries[index];

                        if (string.Equals(entry.FileName, ".", StringComparison.Ordinal) ||
                            string.Equals(entry.FileName, "..", StringComparison.Ordinal))
                        {
                            continue;
                        }

                        results.Add(new OpenCifsClientDirectoryEntry
                        {
                            FileName = entry.FileName,
                            EndOfFile = entry.EndOfFile,
                            AllocationSize = entry.AllocationSize,
                            FileAttributes = entry.FileAttributes,
                            CreationTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(entry.CreationTime),
                            LastAccessTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(entry.LastAccessTime),
                            LastWriteTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(entry.LastWriteTime),
                            ChangeTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(entry.ChangeTime)
                        });
                    }

                    flags = Smb2QueryDirectoryFlags.None;
                }

                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return results.ToArray();
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

        private static uint GetDirectoryQueryBufferLength(OpenCifsClientConnection connection)
        {
            // 64 KiB is the largest output buffer that a single credit covers, so it needs no multi-credit charge
            // on SMB 2.1+ and stays valid on SMB 2.0.2. Never exceed the negotiated transact size.
            uint negotiatedMaximum = connection.Session.NegotiatedMaxTransactSize;

            if (negotiatedMaximum == 0)
            {
                return DefaultDirectoryQueryBufferLength;
            }

            return Math.Min(MaximumDirectoryQueryBufferLength, negotiatedMaximum);
        }

        private static readonly char[] _PathSeparators = new[] { '\\', '/' };
        private readonly OpenCifsShareSession _ShareSession;
    }
}

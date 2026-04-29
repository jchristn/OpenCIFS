namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    /// <summary>
    /// Managed direct-TCP client facade for common authenticated SMB 2.0.2 file and directory operations.
    /// </summary>
    public sealed class OpenCifsClientFacade : IDisposable, IAsyncDisposable
    {
        private const uint DefaultDirectoryQueryBufferLength = 4096;
        private const uint DefaultChangeNotifyBufferLength = 4096;
        private const uint DefaultReadChunkLength = 65536;
        private const uint GenericReadAccess = 0x80000000U;
        private const uint GenericWriteAccess = 0x40000000U;
        private const uint DeleteAccessMask = 0x00010000U;

        /// <summary>
        /// Initialize a managed direct-TCP client facade.
        /// </summary>
        /// <param name="options">Client options.</param>
        public OpenCifsClientFacade(OpenCifsClientOptions options)
        {
            _Connection = new OpenCifsClientConnection(options);
        }

        /// <summary>
        /// Client options.
        /// </summary>
        public OpenCifsClientOptions Options
        {
            get
            {
                return _Connection.Options;
            }
        }

        /// <summary>
        /// Current low-level client session for the active or next connection lifecycle.
        /// </summary>
        public OpenCifsClientSession Session
        {
            get
            {
                return _Connection.Session;
            }
        }

        /// <summary>
        /// Whether a direct-TCP transport connection is currently active.
        /// </summary>
        public bool IsConnected
        {
            get
            {
                return _Connection.IsConnected;
            }
        }

        /// <summary>
        /// Whether the active client session is authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return _Connection.IsAuthenticated;
            }
        }

        /// <summary>
        /// Connect, negotiate, and authenticate against the configured direct-TCP endpoint.
        /// </summary>
        /// <param name="credential">Client credential.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task ConnectAsync(OpenCifsClientCredential credential, CancellationToken cancellationToken = default)
        {
            _TreeHandlesByShare.Clear();
            await _Connection.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Send an authenticated SMB2 echo request across the active direct-TCP session.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public Task EchoAsync(CancellationToken cancellationToken = default)
        {
            return _Connection.EchoAsync(cancellationToken);
        }

        /// <summary>
        /// Create a directory if it does not already exist.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task CreateDirectoryAsync(string shareName, string path, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.OpenIf,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Write the full byte buffer to a file, creating or overwriting it as needed.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task WriteAllBytesAsync(string shareName, string path, byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenAsync(
                treeHandle,
                path,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                if (data.Length == 0)
                {
                    await _Connection.SetEndOfFileAsync(openHandle, 0, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await _Connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
                    uint chunkLength = GetFacadeWriteChunkLength();
                    int offset = 0;

                    while (offset < data.Length)
                    {
                        int bytesRemaining = data.Length - offset;
                        int bytesToWrite = Math.Min(bytesRemaining, checked((int)chunkLength));
                        byte[] chunk = new byte[bytesToWrite];
                        Buffer.BlockCopy(data, offset, chunk, 0, bytesToWrite);
                        uint writtenCount = await _Connection.WriteAsync(openHandle, chunk, checked((ulong)offset), cancellationToken).ConfigureAwait(false);

                        if (writtenCount != bytesToWrite)
                        {
                            throw new InvalidOperationException("The server did not acknowledge the full write length.");
                        }

                        offset += bytesToWrite;
                    }
                }

                await _Connection.FlushAsync(openHandle, cancellationToken).ConfigureAwait(false);
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Read the full contents of a file.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>File bytes.</returns>
        public async Task<byte[]> ReadAllBytesAsync(string shareName, string path, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.NonDirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                await _Connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
                List<byte> bytes = new List<byte>();
                ulong offset = 0;
                uint chunkLength = GetFacadeReadChunkLength();

                while (true)
                {
                    byte[] chunk = await _Connection.ReadAsync(
                        openHandle,
                        chunkLength,
                        offset,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    if (chunk.Length == 0)
                    {
                        break;
                    }

                    bytes.AddRange(chunk);
                    offset += (uint)chunk.Length;

                    if (chunk.Length < chunkLength)
                    {
                        break;
                    }
                }

                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return bytes.ToArray();
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Enumerate a directory through FILE_FULL_DIRECTORY_INFORMATION responses.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative directory path.</param>
        /// <param name="fileNamePattern">Optional search pattern.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded directory entries.</returns>
        public async Task<OpenCifsClientDirectoryEntry[]> EnumerateDirectoryAsync(string shareName, string path, string? fileNamePattern = null, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                byte[] outputBuffer = await _Connection.QueryDirectoryAsync(
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

                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return results;
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Wait for a bounded directory change-notify completion.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative directory path.</param>
        /// <param name="completionFilter">Requested completion filter.</param>
        /// <param name="watchTree">Whether to watch the full subtree beneath the directory.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded change-notify entries.</returns>
        public async Task<OpenCifsClientChangeNotification[]> WaitForDirectoryChangeAsync(
            string shareName,
            string path,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.DirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                FileNotifyInformation[] entries = await _Connection.ChangeNotifyAsync(
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

                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return results;
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Query high-level metadata for an existing file or directory.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded metadata.</returns>
        public async Task<OpenCifsClientFileMetadata> GetMetadataAsync(string shareName, string path, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericReadAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                FileNetworkOpenInformation networkOpenInformation = FileNetworkOpenInformation.ReadFrom(await _Connection.QueryInfoAsync(
                    openHandle,
                    FileInformationClass.NetworkOpenInformation,
                    cancellationToken: cancellationToken).ConfigureAwait(false));
                FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(await _Connection.QueryInfoAsync(
                    openHandle,
                    FileInformationClass.StandardInformation,
                    cancellationToken: cancellationToken).ConfigureAwait(false));
                FileNameInformation nameInformation = FileNameInformation.ReadFrom(await _Connection.QueryInfoAsync(
                    openHandle,
                    FileInformationClass.NameInformation,
                    cancellationToken: cancellationToken).ConfigureAwait(false));

                OpenCifsClientFileMetadata metadata = new OpenCifsClientFileMetadata
                {
                    Path = nameInformation.FileName,
                    IsDirectory = standardInformation.Directory,
                    IsDeletePending = standardInformation.DeletePending,
                    AllocationSize = networkOpenInformation.AllocationSize,
                    EndOfFile = networkOpenInformation.EndOfFile,
                    FileAttributes = networkOpenInformation.FileAttributes,
                    CreationTimeUtc = TryConvertFileTimeToUtcDateTime(networkOpenInformation.CreationTime),
                    LastAccessTimeUtc = TryConvertFileTimeToUtcDateTime(networkOpenInformation.LastAccessTime),
                    LastWriteTimeUtc = TryConvertFileTimeToUtcDateTime(networkOpenInformation.LastWriteTime),
                    ChangeTimeUtc = TryConvertFileTimeToUtcDateTime(networkOpenInformation.ChangeTime)
                };

                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return metadata;
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Rename an existing file or directory within the connected share.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Existing relative path.</param>
        /// <param name="newPath">New relative path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task RenameAsync(string shareName, string path, string newPath, bool replaceIfExists = false, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericReadAccess | DeleteAccessMask,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await _Connection.SetRenameAsync(openHandle, newPath, replaceIfExists, cancellationToken).ConfigureAwait(false);
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Delete an existing file or empty directory.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task DeleteAsync(string shareName, string path, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenExistingPathAsync(
                treeHandle,
                path,
                DeleteAccessMask,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await _Connection.SetDeletePendingAsync(openHandle, deletePending: true, cancellationToken).ConfigureAwait(false);
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Apply a FILE_BASIC_INFORMATION mutation to an existing file or directory.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="fileAttributes">Optional file attributes.</param>
        /// <param name="creationTimeUtc">Optional creation time.</param>
        /// <param name="lastAccessTimeUtc">Optional last-access time.</param>
        /// <param name="lastWriteTimeUtc">Optional last-write time.</param>
        /// <param name="changeTimeUtc">Optional change time.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetBasicInfoAsync(
            string shareName,
            string path,
            ProtocolFileAttributes? fileAttributes = null,
            DateTime? creationTimeUtc = null,
            DateTime? lastAccessTimeUtc = null,
            DateTime? lastWriteTimeUtc = null,
            DateTime? changeTimeUtc = null,
            CancellationToken cancellationToken = default)
        {
            if (fileAttributes == null &&
                creationTimeUtc == null &&
                lastAccessTimeUtc == null &&
                lastWriteTimeUtc == null &&
                changeTimeUtc == null)
            {
                throw new ArgumentException("At least one basic-information value must be specified.", nameof(fileAttributes));
            }

            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericWriteAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                FileBasicInformation information = new FileBasicInformation
                {
                    CreationTime = creationTimeUtc.HasValue ? ToFileTimeUtc(creationTimeUtc.Value) : 0,
                    LastAccessTime = lastAccessTimeUtc.HasValue ? ToFileTimeUtc(lastAccessTimeUtc.Value) : 0,
                    LastWriteTime = lastWriteTimeUtc.HasValue ? ToFileTimeUtc(lastWriteTimeUtc.Value) : 0,
                    ChangeTime = changeTimeUtc.HasValue ? ToFileTimeUtc(changeTimeUtc.Value) : 0,
                    FileAttributes = fileAttributes ?? ProtocolFileAttributes.None
                };

                await _Connection.SetBasicInfoAsync(openHandle, information, cancellationToken).ConfigureAwait(false);
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Apply a FILE_END_OF_FILE_INFORMATION mutation to an existing file.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="path">Relative file path.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetFileLengthAsync(string shareName, string path, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            OpenCifsClientTreeHandle treeHandle = await EnsureTreeConnectedAsync(shareName, cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle openHandle = await _Connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericWriteAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await _Connection.SetEndOfFileAsync(openHandle, endOfFile, cancellationToken).ConfigureAwait(false);
                await _Connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Disconnect all active trees, log off the session, and close the underlying transport.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _TreeHandlesByShare.Clear();
            await _Connection.DisconnectAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _TreeHandlesByShare.Clear();
            _Connection.Dispose();
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            _TreeHandlesByShare.Clear();
            await _Connection.DisposeAsync().ConfigureAwait(false);
        }

        private async Task<OpenCifsClientTreeHandle> EnsureTreeConnectedAsync(string shareName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            string normalizedShareName = shareName.Trim('\\');

            if (_TreeHandlesByShare.TryGetValue(normalizedShareName, out OpenCifsClientTreeHandle? treeHandle) && !treeHandle.IsDisconnected)
            {
                return treeHandle;
            }

            OpenCifsClientTreeHandle connectedTreeHandle = await _Connection.TreeConnectAsync(normalizedShareName, cancellationToken).ConfigureAwait(false);
            _TreeHandlesByShare[normalizedShareName] = connectedTreeHandle;
            return connectedTreeHandle;
        }

        private uint GetFacadeReadChunkLength()
        {
            return GetFacadeReadWriteChunkLength(_Connection.Session.NegotiatedMaxReadSize);
        }

        private uint GetFacadeWriteChunkLength()
        {
            return GetFacadeReadWriteChunkLength(_Connection.Session.NegotiatedMaxWriteSize);
        }

        private uint GetFacadeReadWriteChunkLength(uint negotiatedMaximum)
        {
            if (negotiatedMaximum == 0)
            {
                return DefaultReadChunkLength;
            }

            uint creditBoundLength = checked((uint)Math.Max(1, _Connection.Session.AvailableCredits)) * Smb2CreditChargeHelper.BytesPerCredit;
            return Math.Min(negotiatedMaximum, creditBoundLength);
        }

        private async Task TryCloseOpenAsync(OpenCifsClientOpenHandle openHandle)
        {
            try
            {
                await _Connection.CloseAsync(openHandle, cancellationToken: CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private static DateTime? TryConvertFileTimeToUtcDateTime(ulong value)
        {
            if (value == 0 || value > Int64.MaxValue)
            {
                return null;
            }

            try
            {
                return DateTime.FromFileTimeUtc((long)value);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        private static ulong ToFileTimeUtc(DateTime value)
        {
            DateTime utcValue = value.Kind switch
            {
                DateTimeKind.Utc => value,
                DateTimeKind.Local => value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
            };

            return unchecked((ulong)utcValue.ToFileTimeUtc());
        }

        private readonly Dictionary<string, OpenCifsClientTreeHandle> _TreeHandlesByShare = new Dictionary<string, OpenCifsClientTreeHandle>(StringComparer.OrdinalIgnoreCase);
        private readonly OpenCifsClientConnection _Connection;
    }
}

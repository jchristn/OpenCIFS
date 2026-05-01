namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Grouped share-scoped file operations.
    /// </summary>
    public sealed class OpenCifsShareFileOperations
    {
        private const uint DefaultReadChunkLength = 65536;
        private const uint GenericReadAccess = 0x80000000U;
        private const uint GenericWriteAccess = 0x40000000U;
        private const uint DeleteAccessMask = 0x00010000U;

        internal OpenCifsShareFileOperations(OpenCifsShareSession shareSession)
        {
            _ShareSession = shareSession ?? throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
        }

        /// <summary>
        /// Write the full byte buffer to a file, creating or overwriting it as needed.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task WriteAllBytesAsync(string path, byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => WriteAllBytesCoreAsync(connection, treeHandle, resolvedPath, data, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Write the full byte buffer to a file without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="data">Bytes to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryWriteAllBytesAsync(string path, byte[] data, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WriteAllBytesAsync(path, data, cancellationToken));
        }

        /// <summary>
        /// Read the full contents of a file.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>File bytes.</returns>
        public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => ReadAllBytesCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Read the full contents of a file without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ReadAllBytesAsync(path, cancellationToken));
        }

        /// <summary>
        /// Rename an existing file within the share.
        /// </summary>
        /// <param name="path">Existing relative file path.</param>
        /// <param name="newPath">New relative file path.</param>
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
        /// Rename an existing file within the share without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Existing relative file path.</param>
        /// <param name="newPath">New relative file path.</param>
        /// <param name="replaceIfExists">Whether an existing destination can be replaced.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryRenameAsync(string path, string newPath, bool replaceIfExists = false, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => RenameAsync(path, newPath, replaceIfExists, cancellationToken));
        }

        /// <summary>
        /// Delete an existing file.
        /// </summary>
        /// <param name="path">Relative file path.</param>
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
        /// Delete an existing file without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryDeleteAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => DeleteAsync(path, cancellationToken));
        }

        /// <summary>
        /// Apply a logical end-of-file mutation to an existing file.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetLengthAsync(string path, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => SetLengthCoreAsync(connection, treeHandle, resolvedPath, endOfFile, token)).ConfigureAwait(false);
        }

        private async Task WriteAllBytesCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            byte[] data,
            CancellationToken cancellationToken)
        {
            await connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
            uint chunkLength = GetWriteChunkLength(connection);

            if (data.Length <= chunkLength)
            {
                uint writtenCount = await connection.CompoundCreateWriteFlushCloseAsync(
                    treeHandle,
                    path,
                    data,
                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if (writtenCount != data.Length)
                {
                    throw new OpenCifsClientProtocolException("The server did not acknowledge the full write length.");
                }

                return;
            }

            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                int offset = 0;

                while (offset < data.Length)
                {
                    int bytesRemaining = data.Length - offset;
                    int bytesToWrite = Math.Min(bytesRemaining, checked((int)chunkLength));
                    byte[] chunk = new byte[bytesToWrite];
                    Buffer.BlockCopy(data, offset, chunk, 0, bytesToWrite);
                    uint writtenCount = await connection.WriteAsync(openHandle, chunk, checked((ulong)offset), cancellationToken).ConfigureAwait(false);

                    if (writtenCount != bytesToWrite)
                    {
                        throw new OpenCifsClientProtocolException("The server did not acknowledge the full write length.");
                    }

                    offset += bytesToWrite;
                }

                await connection.FlushAsync(openHandle, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task<byte[]> ReadAllBytesCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            await connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
            uint chunkLength = GetReadChunkLength(connection);
            FileAllInformation allInformation = FileAllInformation.ReadFrom(
                await connection.CompoundCreateQueryInfoCloseAsync(
                    treeHandle,
                    path,
                    FileInformationClass.AllInformation,
                    cancellationToken: cancellationToken).ConfigureAwait(false));

            if (allInformation.StandardInformation.EndOfFile == 0)
            {
                return Array.Empty<byte>();
            }

            if (allInformation.StandardInformation.EndOfFile <= chunkLength &&
                allInformation.StandardInformation.EndOfFile <= UInt32.MaxValue)
            {
                return await connection.CompoundOpenReadCloseAsync(
                    treeHandle,
                    path,
                    checked((uint)allInformation.StandardInformation.EndOfFile),
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.NonDirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                List<byte> bytes = new List<byte>();
                ulong offset = 0;

                while (true)
                {
                    byte[] chunk = await connection.ReadAsync(
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

                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return bytes.ToArray();
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

        private async Task DeleteCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
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

        private async Task SetLengthCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            ulong endOfFile,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericWriteAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await connection.SetEndOfFileAsync(openHandle, endOfFile, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Apply a logical end-of-file mutation without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetLengthAsync(string path, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetLengthAsync(path, endOfFile, cancellationToken));
        }

        private static uint GetReadChunkLength(OpenCifsClientConnection connection)
        {
            return GetReadWriteChunkLength(connection, connection.Session.NegotiatedMaxReadSize);
        }

        private static uint GetWriteChunkLength(OpenCifsClientConnection connection)
        {
            return GetReadWriteChunkLength(connection, connection.Session.NegotiatedMaxWriteSize);
        }

        private static uint GetReadWriteChunkLength(OpenCifsClientConnection connection, uint negotiatedMaximum)
        {
            if (negotiatedMaximum == 0)
            {
                return DefaultReadChunkLength;
            }

            uint creditBoundLength = checked((uint)Math.Max(1, connection.Session.AvailableCredits)) * Smb2CreditChargeHelper.BytesPerCredit;
            return Math.Min(negotiatedMaximum, creditBoundLength);
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}


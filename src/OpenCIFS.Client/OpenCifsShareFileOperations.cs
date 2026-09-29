namespace OpenCIFS.Client
{
    using System;
    using System.IO;
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
        private const uint FileShareRead = 0x00000001U;
        private const ulong MaximumBufferedLength = 0x7FFFFFC7UL;

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
        /// <remarks>
        /// The result is bounded by the end-of-file observed when the read starts: short server reads are continued until
        /// that length is reached, bytes appended by other writers during the read are not included, and a file that
        /// shrinks returns the bytes that remained. Files larger than a single array can hold fail with
        /// <see cref="OpenCifsClientStateException"/>; use <see cref="OpenReadAsync"/> or <see cref="ReadAsync"/> instead.
        /// </remarks>
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
        /// Read a byte range from a file.
        /// </summary>
        /// <remarks>
        /// Returns fewer than <paramref name="count"/> bytes when the range extends past end-of-file, and an empty
        /// array when <paramref name="offset"/> is at or beyond end-of-file. Large ranges are split into reads bounded
        /// by the negotiated maximum read size and available credits, and short server reads are continued until the
        /// range is complete.
        /// </remarks>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Zero-based byte offset of the first byte to read.</param>
        /// <param name="count">Maximum number of bytes to read. Must be greater than or equal to zero.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Bytes read from the range.</returns>
        public async Task<byte[]> ReadAsync(string path, ulong offset, int count, CancellationToken cancellationToken = default)
        {
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be greater than or equal to zero.");
            }

            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => ReadRangeCoreAsync(connection, treeHandle, resolvedPath, offset, count, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Read a byte range from a file without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="offset">Zero-based byte offset of the first byte to read.</param>
        /// <param name="count">Maximum number of bytes to read. Must be greater than or equal to zero.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<byte[]>> TryReadAsync(string path, ulong offset, int count, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ReadAsync(path, offset, count, cancellationToken));
        }

        /// <summary>
        /// Open a file for streaming reads.
        /// </summary>
        /// <remarks>
        /// The returned stream is read-only and seekable and holds an open SMB handle until it is disposed. The handle is
        /// opened with generic read access and <c>FILE_SHARE_READ</c>, so other readers can open the file while writers
        /// and deleters are refused. Reads are lazy and chunked by the negotiated maximum read size. Its <see cref="Stream.Length"/> is the file's end-of-file at open time. Disposing the stream closes the
        /// handle on a best-effort basis and never throws. The stream shares the parent client connection, so its reads
        /// are serialized with other operations on the same client.
        /// </remarks>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Read-only, seekable stream over the file contents.</returns>
        public async Task<Stream> OpenReadAsync(string path, CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => OpenReadCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Open a file for streaming reads without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<Stream>> TryOpenReadAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => OpenReadAsync(path, cancellationToken));
        }

        /// <summary>
        /// Write a file from a stream, creating it or truncating and overwriting existing content.
        /// </summary>
        /// <remarks>
        /// Data is streamed in chunks bounded by the negotiated maximum write size, so the source does not need to be
        /// seekable and is never buffered in full. When <paramref name="length"/> is null the source is read until it
        /// ends; otherwise exactly <paramref name="length"/> bytes are written and an <see cref="EndOfStreamException"/>
        /// is thrown if the source ends early (the destination may then contain the bytes written so far). A zero
        /// length or an empty source produces an empty file. The handle is flushed and closed on success and closed on
        /// failure.
        /// </remarks>
        /// <param name="path">Relative file path.</param>
        /// <param name="source">Readable source stream.</param>
        /// <param name="length">Exact number of bytes to write, or null to write until the source ends.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task WriteAsync(string path, Stream source, long? length = null, CancellationToken cancellationToken = default)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source), "Source cannot be null.");
            }

            if (!source.CanRead)
            {
                throw new ArgumentException("Source must be readable.", nameof(source));
            }

            if (length.HasValue && length.Value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than or equal to zero.");
            }

            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => WriteFromStreamCoreAsync(connection, treeHandle, resolvedPath, source, length, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Write a file from a stream without throwing for typed client failures.
        /// </summary>
        /// <remarks>
        /// Argument-validation failures and <see cref="EndOfStreamException"/> for a short source still throw.
        /// </remarks>
        /// <param name="path">Relative file path.</param>
        /// <param name="source">Readable source stream.</param>
        /// <param name="length">Exact number of bytes to write, or null to write until the source ends.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TryWriteAsync(string path, Stream source, long? length = null, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => WriteAsync(path, source, length, cancellationToken));
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
                    desiredAccess: GenericReadAccess,
                    cancellationToken: cancellationToken).ConfigureAwait(false));

            ulong endOfFile = allInformation.StandardInformation.EndOfFile;

            if (endOfFile == 0)
            {
                return Array.Empty<byte>();
            }

            if (endOfFile > MaximumBufferedLength)
            {
                throw new OpenCifsClientStateException(
                    "The file is " + endOfFile + " bytes, which exceeds the largest single byte array ReadAllBytesAsync can return. Use OpenReadAsync or ReadAsync instead.");
            }

            // The result is a snapshot bounded by the EOF observed up front: bytes appended by other writers while
            // the read is in progress are not included, and a file that shrinks returns the bytes that remained.
            byte[] buffer = new byte[(int)endOfFile];
            int filled = 0;

            if (endOfFile <= chunkLength)
            {
                byte[] firstChunk = await connection.CompoundOpenReadCloseAsync(
                    treeHandle,
                    path,
                    checked((uint)endOfFile),
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                int firstCount = Math.Min(firstChunk.Length, buffer.Length);
                Buffer.BlockCopy(firstChunk, 0, buffer, 0, firstCount);
                filled = firstCount;

                if (filled == buffer.Length || firstChunk.Length == 0)
                {
                    return filled == buffer.Length ? buffer : TrimBuffer(buffer, filled);
                }
            }

            // Either the file spans several chunks or the server returned a legal short read. SMB servers may
            // return fewer bytes than requested before EOF, so keep reading until the expected length is reached
            // or the server reports end-of-file.
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.NonDirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                filled += await ReadIntoBufferAsync(connection, openHandle, (ulong)filled, buffer, filled, buffer.Length - filled, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return filled == buffer.Length ? buffer : TrimBuffer(buffer, filled);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task<byte[]> ReadRangeCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            ulong offset,
            int count,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.NonDirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                byte[] result = Array.Empty<byte>();

                if (count > 0)
                {
                    FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(
                        await connection.QueryInfoAsync(openHandle, FileInformationClass.StandardInformation, cancellationToken: cancellationToken).ConfigureAwait(false));

                    if (offset < standardInformation.EndOfFile)
                    {
                        int boundedCount = (int)Math.Min((ulong)count, standardInformation.EndOfFile - offset);
                        byte[] buffer = new byte[boundedCount];
                        await connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
                        int filled = await ReadIntoBufferAsync(connection, openHandle, offset, buffer, 0, boundedCount, cancellationToken).ConfigureAwait(false);
                        result = filled == buffer.Length ? buffer : TrimBuffer(buffer, filled);
                    }
                }

                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                return result;
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task<Stream> OpenReadCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            if (!ReferenceEquals(treeHandle, _ShareSession.TreeHandle))
            {
                throw new OpenCifsClientStateException(
                    "OpenReadAsync does not support DFS referrals that resolve to a different share. Use ReadAsync or ReadAllBytesAsync for that path.");
            }

            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                desiredAccess: GenericReadAccess,
                shareAccess: FileShareRead,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: Smb2CreateOptions.NonDirectoryFile,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(
                    await connection.QueryInfoAsync(openHandle, FileInformationClass.StandardInformation, cancellationToken: cancellationToken).ConfigureAwait(false));
                await connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
                return new OpenCifsShareReadStream(
                    _ShareSession,
                    openHandle,
                    checked((long)standardInformation.EndOfFile),
                    checked((int)GetReadChunkLength(connection)));
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task WriteFromStreamCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            Stream source,
            long? length,
            CancellationToken cancellationToken)
        {
            await connection.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
            int chunkLength = checked((int)GetWriteChunkLength(connection));
            OpenCifsClientOpenHandle openHandle = await connection.OpenAsync(
                treeHandle,
                path,
                createDisposition: Smb2CreateDisposition.OverwriteIf,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                byte[] buffer = new byte[length.HasValue ? (int)Math.Min(chunkLength, length.Value) : chunkLength];
                ulong offset = 0;
                long remaining = length ?? -1;

                while (remaining != 0)
                {
                    int toRead = remaining < 0 ? buffer.Length : (int)Math.Min(buffer.Length, remaining);
                    int filled = 0;

                    while (filled < toRead)
                    {
                        int read = await source.ReadAsync(buffer.AsMemory(filled, toRead - filled), cancellationToken).ConfigureAwait(false);

                        if (read == 0)
                        {
                            break;
                        }

                        filled += read;
                    }

                    if (filled > 0)
                    {
                        byte[] chunk = filled == buffer.Length ? buffer : buffer.AsSpan(0, filled).ToArray();
                        uint writtenCount = await connection.WriteAsync(openHandle, chunk, offset, cancellationToken).ConfigureAwait(false);

                        if (writtenCount != filled)
                        {
                            throw new OpenCifsClientProtocolException("The server did not acknowledge the full write length.");
                        }

                        offset += (ulong)filled;
                    }

                    if (filled < toRead)
                    {
                        if (remaining > 0)
                        {
                            throw new EndOfStreamException(
                                "The source stream ended after " + offset + " bytes, before the requested length of " + length!.Value + " bytes was written.");
                        }

                        break;
                    }

                    if (remaining > 0)
                    {
                        remaining -= filled;
                    }
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

        private static async Task<int> ReadIntoBufferAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientOpenHandle openHandle,
            ulong fileOffset,
            byte[] buffer,
            int bufferOffset,
            int count,
            CancellationToken cancellationToken)
        {
            int total = 0;

            while (total < count)
            {
                uint chunkLength = GetReadChunkLength(connection);
                uint requestLength = (uint)Math.Min(chunkLength, (uint)(count - total));
                byte[] chunk = await connection.ReadAsync(
                    openHandle,
                    requestLength,
                    fileOffset + (ulong)total,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if (chunk.Length == 0)
                {
                    // STATUS_END_OF_FILE or a zero-length read: the file ended before the expected length.
                    break;
                }

                int copyCount = Math.Min(chunk.Length, count - total);
                Buffer.BlockCopy(chunk, 0, buffer, bufferOffset + total, copyCount);
                total += copyCount;
            }

            return total;
        }

        private static byte[] TrimBuffer(byte[] buffer, int length)
        {
            byte[] trimmed = new byte[length];
            Buffer.BlockCopy(buffer, 0, trimmed, 0, length);
            return trimmed;
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

            // Servers such as Samba negotiate up to 8 MiB per READ or WRITE, but the direct-TCP transport bounds each
            // frame at 1 MiB of payload plus header headroom. Never request more per operation than a frame can carry.
            uint creditBoundLength = checked((uint)Math.Max(1, connection.Session.AvailableCredits)) * Smb2CreditChargeHelper.BytesPerCredit;
            return Math.Min(Math.Min(negotiatedMaximum, creditBoundLength), Smb2CreditChargeHelper.ImplementedLargeReadWriteSize);
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}


namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    /// <summary>
    /// Grouped share-scoped metadata operations.
    /// </summary>
    public sealed class OpenCifsShareMetadataOperations
    {
        private const uint GenericReadAccess = 0x80000000U;
        private const uint GenericWriteAccess = 0x40000000U;

        internal OpenCifsShareMetadataOperations(OpenCifsShareSession shareSession)
        {
            _ShareSession = shareSession ?? throw new ArgumentNullException(nameof(shareSession), "ShareSession cannot be null.");
        }

        /// <summary>
        /// Query high-level metadata for an existing file or directory.
        /// </summary>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Decoded metadata.</returns>
        public async Task<OpenCifsClientFileMetadata> GetAttributesAsync(string path, CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => GetAttributesCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Query high-level metadata without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<OpenCifsClientFileMetadata>> TryGetAttributesAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => GetAttributesAsync(path, cancellationToken));
        }

        /// <summary>
        /// Apply a FILE_BASIC_INFORMATION mutation to an existing file or directory.
        /// </summary>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="fileAttributes">Optional file attributes.</param>
        /// <param name="creationTimeUtc">Optional creation time.</param>
        /// <param name="lastAccessTimeUtc">Optional last-access time.</param>
        /// <param name="lastWriteTimeUtc">Optional last-write time.</param>
        /// <param name="changeTimeUtc">Optional change time.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetBasicInfoAsync(
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

            FileBasicInformation information = new FileBasicInformation
            {
                CreationTime = creationTimeUtc.HasValue ? ToFileTimeUtc(creationTimeUtc.Value) : 0,
                LastAccessTime = lastAccessTimeUtc.HasValue ? ToFileTimeUtc(lastAccessTimeUtc.Value) : 0,
                LastWriteTime = lastWriteTimeUtc.HasValue ? ToFileTimeUtc(lastWriteTimeUtc.Value) : 0,
                ChangeTime = changeTimeUtc.HasValue ? ToFileTimeUtc(changeTimeUtc.Value) : 0,
                FileAttributes = fileAttributes ?? ProtocolFileAttributes.None
            };
            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => SetBasicInfoCoreAsync(connection, treeHandle, resolvedPath, information, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Apply a FILE_BASIC_INFORMATION mutation without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="fileAttributes">Optional file attributes.</param>
        /// <param name="creationTimeUtc">Optional creation time.</param>
        /// <param name="lastAccessTimeUtc">Optional last-access time.</param>
        /// <param name="lastWriteTimeUtc">Optional last-write time.</param>
        /// <param name="changeTimeUtc">Optional change time.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetBasicInfoAsync(
            string path,
            ProtocolFileAttributes? fileAttributes = null,
            DateTime? creationTimeUtc = null,
            DateTime? lastAccessTimeUtc = null,
            DateTime? lastWriteTimeUtc = null,
            DateTime? changeTimeUtc = null,
            CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetBasicInfoAsync(
                path,
                fileAttributes,
                creationTimeUtc,
                lastAccessTimeUtc,
                lastWriteTimeUtc,
                changeTimeUtc,
                cancellationToken));
        }

        /// <summary>
        /// Apply a FILE_END_OF_FILE_INFORMATION mutation to an existing file.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public async Task SetFileLengthAsync(string path, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => SetFileLengthCoreAsync(connection, treeHandle, resolvedPath, endOfFile, token)).ConfigureAwait(false);
        }

        private static async Task<OpenCifsClientFileMetadata> GetAttributesCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            try
            {
                return CreateMetadataFromAllInformation(
                    FileAllInformation.ReadFrom(
                        await connection.CompoundCreateQueryInfoCloseAsync(
                            treeHandle,
                            path,
                            FileInformationClass.AllInformation,
                            desiredAccess: GenericReadAccess,
                            createDisposition: Smb2CreateDisposition.Open,
                            createOptions: Smb2CreateOptions.NonDirectoryFile,
                            cancellationToken: cancellationToken).ConfigureAwait(false)));
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.FileIsADirectory)
            {
                return CreateMetadataFromAllInformation(
                    FileAllInformation.ReadFrom(
                        await connection.CompoundCreateQueryInfoCloseAsync(
                            treeHandle,
                            path,
                            FileInformationClass.AllInformation,
                            desiredAccess: GenericReadAccess,
                            createDisposition: Smb2CreateDisposition.Open,
                            createOptions: Smb2CreateOptions.DirectoryFile,
                            cancellationToken: cancellationToken).ConfigureAwait(false)));
            }
        }

        private async Task SetBasicInfoCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            FileBasicInformation information,
            CancellationToken cancellationToken)
        {
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                GenericWriteAccess,
                cancellationToken).ConfigureAwait(false);

            try
            {
                await connection.SetBasicInfoAsync(openHandle, information, cancellationToken).ConfigureAwait(false);
                await connection.CloseAsync(openHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await _ShareSession.TryCloseOpenAsync(openHandle).ConfigureAwait(false);
                throw;
            }
        }

        private async Task SetFileLengthCoreAsync(
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
        /// Apply a FILE_END_OF_FILE_INFORMATION mutation without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file path.</param>
        /// <param name="endOfFile">Requested logical EOF length.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult> TrySetFileLengthAsync(string path, ulong endOfFile, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => SetFileLengthAsync(path, endOfFile, cancellationToken));
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

        private static OpenCifsClientFileMetadata CreateMetadataFromAllInformation(FileAllInformation information)
        {
            return new OpenCifsClientFileMetadata
            {
                Path = information.NameInformation.FileName,
                IsDirectory = information.StandardInformation.Directory,
                IsDeletePending = information.StandardInformation.DeletePending,
                AllocationSize = information.StandardInformation.AllocationSize,
                EndOfFile = information.StandardInformation.EndOfFile,
                FileAttributes = information.BasicInformation.FileAttributes,
                CreationTimeUtc = TryConvertFileTimeToUtcDateTime(information.BasicInformation.CreationTime),
                LastAccessTimeUtc = TryConvertFileTimeToUtcDateTime(information.BasicInformation.LastAccessTime),
                LastWriteTimeUtc = TryConvertFileTimeToUtcDateTime(information.BasicInformation.LastWriteTime),
                ChangeTimeUtc = TryConvertFileTimeToUtcDateTime(information.BasicInformation.ChangeTime)
            };
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}

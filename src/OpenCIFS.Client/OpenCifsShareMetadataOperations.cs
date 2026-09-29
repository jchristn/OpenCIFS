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
        private const uint ReadAttributesAccess = 0x00000080U;
        private const uint WriteAttributesAccess = 0x00000100U;

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
        /// Determine whether a file or directory exists at the specified path.
        /// </summary>
        /// <remarks>
        /// Returns <c>false</c> when the server reports a not-found status for the target or any ancestor
        /// (<c>STATUS_OBJECT_NAME_NOT_FOUND</c>, <c>STATUS_OBJECT_PATH_NOT_FOUND</c>, <c>STATUS_NO_SUCH_FILE</c>,
        /// or <c>STATUS_NOT_A_DIRECTORY</c> for a file used as a path component) and when the target is already
        /// delete-pending (<c>STATUS_DELETE_PENDING</c>). Every other failure, including access denied, propagates.
        /// </remarks>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True when a file or directory exists at the path.</returns>
        public async Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
        {
            return await _ShareSession.ExecuteSinglePathAsync(
                path,
                cancellationToken,
                (connection, treeHandle, resolvedPath, token) => ExistsCoreAsync(connection, treeHandle, resolvedPath, token)).ConfigureAwait(false);
        }

        /// <summary>
        /// Determine whether a file or directory exists without throwing for typed client failures.
        /// </summary>
        /// <param name="path">Relative file or directory path.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Non-throwing result envelope.</returns>
        public Task<OpenCifsClientResult<bool>> TryExistsAsync(string path, CancellationToken cancellationToken = default)
        {
            return OpenCifsClientResultFactory.TryAsync(() => ExistsAsync(path, cancellationToken));
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
                CreationTime = creationTimeUtc.HasValue ? OpenCifsClientFileTime.ToFileTimeUtc(creationTimeUtc.Value) : 0,
                LastAccessTime = lastAccessTimeUtc.HasValue ? OpenCifsClientFileTime.ToFileTimeUtc(lastAccessTimeUtc.Value) : 0,
                LastWriteTime = lastWriteTimeUtc.HasValue ? OpenCifsClientFileTime.ToFileTimeUtc(lastWriteTimeUtc.Value) : 0,
                ChangeTime = changeTimeUtc.HasValue ? OpenCifsClientFileTime.ToFileTimeUtc(changeTimeUtc.Value) : 0,
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

        private static async Task<bool> ExistsCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            try
            {
                // Neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE is set, so files and directories both
                // open; FILE_READ_ATTRIBUTES keeps the probe from conflicting with most existing share modes.
                await connection.CompoundCreateQueryInfoCloseAsync(
                    treeHandle,
                    path,
                    FileInformationClass.BasicInformation,
                    desiredAccess: ReadAttributesAccess,
                    createDisposition: Smb2CreateDisposition.Open,
                    createOptions: Smb2CreateOptions.None,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (OpenCifsStatusException exception) when (IsNotFoundStatus(exception.Status))
            {
                return false;
            }
        }

        private static bool IsShareRootPath(string path)
        {
            return path != null && path.Trim().Trim('/', '\\').Length == 0;
        }

        private static bool IsNotFoundStatus(NtStatus status)
        {
            switch (status)
            {
                case NtStatus.ObjectNameNotFound:
                case NtStatus.ObjectPathNotFound:
                case NtStatus.NoSuchFile:
                case NtStatus.NotADirectory:
                case NtStatus.DeletePending:
                    return true;
                default:
                    return false;
            }
        }

        private static async Task<OpenCifsClientFileMetadata> GetAttributesCoreAsync(
            OpenCifsClientConnection connection,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            if (IsShareRootPath(path))
            {
                // The share root is always a directory and SMB2 rejects non-directory opens with an empty name.
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
            // FILE_WRITE_ATTRIBUTES is all FILE_BASIC_INFORMATION needs; GENERIC_WRITE would be refused for read-only
            // files, which made it impossible to clear the read-only attribute.
            OpenCifsClientOpenHandle openHandle = await connection.OpenExistingPathAsync(
                treeHandle,
                path,
                WriteAttributesAccess,
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
                CreationTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(information.BasicInformation.CreationTime),
                LastAccessTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(information.BasicInformation.LastAccessTime),
                LastWriteTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(information.BasicInformation.LastWriteTime),
                ChangeTimeUtc = OpenCifsClientFileTime.ToUtcDateTimeOrNull(information.BasicInformation.ChangeTime)
            };
        }

        private readonly OpenCifsShareSession _ShareSession;
    }
}

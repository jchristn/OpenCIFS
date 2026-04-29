namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    /// <summary>
    /// Backend contract for a registered SMB share.
    /// </summary>
    public abstract class OpenCifsServerShareBackend
    {
        /// <summary>
        /// Share name exposed to SMB clients.
        /// </summary>
        public abstract string ShareName { get; set; }

        /// <summary>
        /// Root path used for share-relative path resolution.
        /// </summary>
        public abstract string RootPath { get; set; }

        /// <summary>
        /// Whether the share root should be created during registration when missing.
        /// </summary>
        public abstract bool CreateRootIfMissing { get; set; }

        /// <summary>
        /// Declared backend capabilities.
        /// </summary>
        public abstract OpenCifsServerShareCapabilities Capabilities { get; }

        /// <summary>
        /// Validate the backend definition before registration.
        /// </summary>
        public abstract void Validate();

        /// <summary>
        /// Clone the backend definition for builder and host registration isolation.
        /// </summary>
        /// <returns>Cloned backend definition.</returns>
        public abstract OpenCifsServerShareBackend Clone();

        /// <summary>
        /// Determine whether a directory exists.
        /// </summary>
        public abstract bool DirectoryExists(string fullPath);

        /// <summary>
        /// Determine whether a file exists.
        /// </summary>
        public abstract bool FileExists(string fullPath);

        /// <summary>
        /// Open a file stream for the resolved backing path.
        /// </summary>
        public abstract FileStream OpenFile(string fullPath, FileMode fileMode, FileAccess fileAccess, FileShare fileShare);

        /// <summary>
        /// Set filesystem attributes for the resolved backing path.
        /// </summary>
        public abstract void SetAttributes(string fullPath, FileAttributes attributes);

        /// <summary>
        /// Read filesystem attributes for the resolved backing path.
        /// </summary>
        public abstract FileAttributes GetAttributes(string fullPath);

        /// <summary>
        /// Create a directory at the resolved backing path.
        /// </summary>
        public abstract void CreateDirectory(string fullPath);

        /// <summary>
        /// Move a file or directory between resolved backing paths.
        /// </summary>
        public abstract void Move(string sourceFullPath, string destinationFullPath, bool isDirectory);

        /// <summary>
        /// Delete a file when present.
        /// </summary>
        public abstract bool DeleteFileIfPresent(string fullPath);

        /// <summary>
        /// Delete a directory when present.
        /// </summary>
        public abstract bool DeleteDirectoryIfPresent(string fullPath, bool recursive);

        /// <summary>
        /// Resolve metadata for a file or directory.
        /// </summary>
        public abstract FileSystemInfo GetFileSystemInfo(string fullPath);

        /// <summary>
        /// Enumerate immediate children for a directory.
        /// </summary>
        public abstract IReadOnlyList<FileSystemInfo> EnumerateFileSystemInfos(string fullPath);

        /// <summary>
        /// Set creation time in UTC.
        /// </summary>
        public abstract void SetCreationTimeUtc(string fullPath, DateTime utcValue, bool isDirectory);

        /// <summary>
        /// Set last-access time in UTC.
        /// </summary>
        public abstract void SetLastAccessTimeUtc(string fullPath, DateTime utcValue, bool isDirectory);

        /// <summary>
        /// Set last-write time in UTC.
        /// </summary>
        public abstract void SetLastWriteTimeUtc(string fullPath, DateTime utcValue, bool isDirectory);
    }
}

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    /// <summary>
    /// Local filesystem-backed share provider for the current server-host surface.
    /// </summary>
    public sealed class OpenCifsServerFileSystemShare : OpenCifsServerShareBackend
    {
        /// <summary>
        /// Share name exposed to SMB clients.
        /// </summary>
        public override string ShareName
        {
            get
            {
                return _ShareName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(ShareName), "ShareName cannot be null or whitespace.");
                }

                _ShareName = value;
            }
        }

        /// <summary>
        /// Filesystem root path exposed for the share.
        /// </summary>
        public override string RootPath
        {
            get
            {
                return _RootPath;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(RootPath), "RootPath cannot be null or whitespace.");
                }

                _RootPath = value;
            }
        }

        /// <summary>
        /// Whether the filesystem root should be created during registration when missing.
        /// Default value: <c>true</c>.
        /// </summary>
        public override bool CreateRootIfMissing { get; set; } = true;

        /// <summary>
        /// Declared backend capabilities for the local filesystem provider.
        /// </summary>
        public override OpenCifsServerShareCapabilities Capabilities { get; } = new OpenCifsServerShareCapabilities
        {
            SupportsFiles = true,
            SupportsDirectories = true,
            SupportsMetadata = true,
            SupportsLocking = true,
            SupportsNotifications = true,
            SupportsNamedStreams = false
        };

        /// <summary>
        /// Validate the share definition.
        /// </summary>
        public override void Validate()
        {
            if (string.IsNullOrWhiteSpace(ShareName))
            {
                throw new ArgumentException("ShareName cannot be null or whitespace.", nameof(ShareName));
            }

            if (string.IsNullOrWhiteSpace(RootPath))
            {
                throw new ArgumentException("RootPath cannot be null or whitespace.", nameof(RootPath));
            }
        }

        /// <summary>
        /// Clone the provider definition.
        /// </summary>
        /// <returns>Cloned provider definition.</returns>
        public override OpenCifsServerShareBackend Clone()
        {
            return new OpenCifsServerFileSystemShare
            {
                ShareName = ShareName,
                RootPath = RootPath,
                CreateRootIfMissing = CreateRootIfMissing
            };
        }

        /// <inheritdoc />
        public override bool DirectoryExists(string fullPath)
        {
            return Directory.Exists(fullPath);
        }

        /// <inheritdoc />
        public override bool FileExists(string fullPath)
        {
            return File.Exists(fullPath);
        }

        /// <inheritdoc />
        public override FileStream OpenFile(string fullPath, FileMode fileMode, FileAccess fileAccess, FileShare fileShare)
        {
            return new FileStream(fullPath, fileMode, fileAccess, fileShare);
        }

        /// <inheritdoc />
        public override void SetAttributes(string fullPath, FileAttributes attributes)
        {
            File.SetAttributes(fullPath, attributes);
        }

        /// <inheritdoc />
        public override FileAttributes GetAttributes(string fullPath)
        {
            return File.GetAttributes(fullPath);
        }

        /// <inheritdoc />
        public override void CreateDirectory(string fullPath)
        {
            Directory.CreateDirectory(fullPath);
        }

        /// <inheritdoc />
        public override void Move(string sourceFullPath, string destinationFullPath, bool isDirectory)
        {
            if (isDirectory)
            {
                Directory.Move(sourceFullPath, destinationFullPath);
                return;
            }

            File.Move(sourceFullPath, destinationFullPath);
        }

        /// <inheritdoc />
        public override bool DeleteFileIfPresent(string fullPath)
        {
            if (!File.Exists(fullPath))
            {
                return false;
            }

            File.Delete(fullPath);
            return true;
        }

        /// <inheritdoc />
        public override bool DeleteDirectoryIfPresent(string fullPath, bool recursive)
        {
            if (!Directory.Exists(fullPath))
            {
                return false;
            }

            Directory.Delete(fullPath, recursive);
            return true;
        }

        /// <inheritdoc />
        public override FileSystemInfo GetFileSystemInfo(string fullPath)
        {
            if (Directory.Exists(fullPath))
            {
                return new DirectoryInfo(fullPath);
            }

            return new FileInfo(fullPath);
        }

        /// <inheritdoc />
        public override IReadOnlyList<FileSystemInfo> EnumerateFileSystemInfos(string fullPath)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(fullPath);
            List<FileSystemInfo> entries = new List<FileSystemInfo>();

            foreach (FileSystemInfo entry in directoryInfo.EnumerateFileSystemInfos())
            {
                entries.Add(entry);
            }

            return entries;
        }

        /// <inheritdoc />
        public override void SetCreationTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            if (isDirectory)
            {
                Directory.SetCreationTimeUtc(fullPath, utcValue);
                return;
            }

            File.SetCreationTimeUtc(fullPath, utcValue);
        }

        /// <inheritdoc />
        public override void SetLastAccessTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            if (isDirectory)
            {
                Directory.SetLastAccessTimeUtc(fullPath, utcValue);
                return;
            }

            File.SetLastAccessTimeUtc(fullPath, utcValue);
        }

        /// <inheritdoc />
        public override void SetLastWriteTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            if (isDirectory)
            {
                Directory.SetLastWriteTimeUtc(fullPath, utcValue);
                return;
            }

            File.SetLastWriteTimeUtc(fullPath, utcValue);
        }

        private string _ShareName = string.Empty;
        private string _RootPath = string.Empty;
    }
}

namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Immutable public snapshot of a share exposed by an OpenCIFS server surface.
    /// </summary>
    public sealed class OpenCifsServerShareInfo
    {
        internal OpenCifsServerShareInfo(
            string shareName,
            string rootPath,
            bool createRootIfMissing,
            string backendKind,
            bool isImplicitOptionsShare,
            OpenCifsServerShareCapabilities capabilities)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(rootPath))
            {
                throw new ArgumentNullException(nameof(rootPath), "RootPath cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(backendKind))
            {
                throw new ArgumentNullException(nameof(backendKind), "BackendKind cannot be null or whitespace.");
            }

            if (capabilities == null)
            {
                throw new ArgumentNullException(nameof(capabilities), "Capabilities cannot be null.");
            }

            ShareName = shareName;
            RootPath = rootPath;
            CreateRootIfMissing = createRootIfMissing;
            BackendKind = backendKind;
            IsImplicitOptionsShare = isImplicitOptionsShare;
            SupportsFiles = capabilities.SupportsFiles;
            SupportsDirectories = capabilities.SupportsDirectories;
            SupportsMetadata = capabilities.SupportsMetadata;
            SupportsLocking = capabilities.SupportsLocking;
            SupportsNotifications = capabilities.SupportsNotifications;
            SupportsNamedStreams = capabilities.SupportsNamedStreams;
        }

        /// <summary>
        /// Share name exposed to SMB clients.
        /// </summary>
        public string ShareName { get; }

        /// <summary>
        /// Resolved root path for the share.
        /// </summary>
        public string RootPath { get; }

        /// <summary>
        /// Whether the share root is created automatically when missing.
        /// </summary>
        public bool CreateRootIfMissing { get; }

        /// <summary>
        /// Server-side backend type name for the share.
        /// </summary>
        public string BackendKind { get; }

        /// <summary>
        /// Whether this share comes from the implicit legacy options-based fallback rather than an explicit registration.
        /// </summary>
        public bool IsImplicitOptionsShare { get; }

        /// <summary>
        /// Whether regular file opens are supported.
        /// </summary>
        public bool SupportsFiles { get; }

        /// <summary>
        /// Whether directory opens are supported.
        /// </summary>
        public bool SupportsDirectories { get; }

        /// <summary>
        /// Whether metadata query and mutation are supported.
        /// </summary>
        public bool SupportsMetadata { get; }

        /// <summary>
        /// Whether the share supports the current locking surface.
        /// </summary>
        public bool SupportsLocking { get; }

        /// <summary>
        /// Whether the share supports the current change-notify surface.
        /// </summary>
        public bool SupportsNotifications { get; }

        /// <summary>
        /// Whether the share supports named streams.
        /// </summary>
        public bool SupportsNamedStreams { get; }
    }
}

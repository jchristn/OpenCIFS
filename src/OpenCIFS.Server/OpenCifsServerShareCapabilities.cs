namespace OpenCIFS.Server
{
    /// <summary>
    /// Declared backend capabilities for a registered SMB share surface.
    /// </summary>
    public sealed class OpenCifsServerShareCapabilities
    {
        /// <summary>
        /// Whether regular file opens are supported.
        /// </summary>
        public bool SupportsFiles { get; set; } = true;

        /// <summary>
        /// Whether directory opens are supported.
        /// </summary>
        public bool SupportsDirectories { get; set; } = true;

        /// <summary>
        /// Whether metadata query and mutation are supported.
        /// </summary>
        public bool SupportsMetadata { get; set; } = true;

        /// <summary>
        /// Whether the backend can participate in the current locking surface.
        /// </summary>
        public bool SupportsLocking { get; set; } = true;

        /// <summary>
        /// Whether the backend can participate in the current change-notify surface.
        /// </summary>
        public bool SupportsNotifications { get; set; } = true;

        /// <summary>
        /// Whether named streams are supported.
        /// </summary>
        public bool SupportsNamedStreams { get; set; }
    }
}

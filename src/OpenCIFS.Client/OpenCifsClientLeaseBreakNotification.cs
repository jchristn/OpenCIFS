namespace OpenCIFS.Client
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Client-visible result for an unsolicited SMB2 lease-break notification.
    /// </summary>
    public sealed class OpenCifsClientLeaseBreakNotification
    {
        /// <summary>
        /// Share name that owns the affected open.
        /// </summary>
        public string ShareName { get; set; } = string.Empty;

        /// <summary>
        /// Affected relative path.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Persistent file identifier for the affected open.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier for the affected open.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Lease state held before the notification was applied.
        /// </summary>
        public Smb2LeaseState PreviousLeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// New lease state requested by the server.
        /// </summary>
        public Smb2LeaseState NewLeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// Whether the client sent a lease-break acknowledgment for this notification.
        /// </summary>
        public bool WasAcknowledged { get; set; }
    }
}

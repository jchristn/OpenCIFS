namespace OpenCIFS.Client
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Client-visible result for an unsolicited SMB2 oplock-break notification.
    /// </summary>
    public sealed class OpenCifsClientOplockBreakNotification
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
        /// Oplock level held before the notification was applied.
        /// </summary>
        public Smb2OplockLevel PreviousOplockLevel { get; set; } = Smb2OplockLevel.None;

        /// <summary>
        /// New oplock level requested by the server.
        /// </summary>
        public Smb2OplockLevel NewOplockLevel { get; set; } = Smb2OplockLevel.None;

        /// <summary>
        /// Whether the client sent an oplock-break acknowledgment for this notification.
        /// </summary>
        public bool WasAcknowledged { get; set; }
    }
}

namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 header flags.
    /// </summary>
    [Flags]
    public enum Smb1HeaderFlags : byte
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Case-insensitive paths.
        /// </summary>
        CaseInsensitive = 0x08,

        /// <summary>
        /// Canonicalized paths.
        /// </summary>
        CanonicalizedPaths = 0x10,

        /// <summary>
        /// Opportunistic locking supported.
        /// </summary>
        OpportunisticLock = 0x20,

        /// <summary>
        /// Notification requested.
        /// </summary>
        Notify = 0x40,

        /// <summary>
        /// Reply packet.
        /// </summary>
        Reply = 0x80
    }
}


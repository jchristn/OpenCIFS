namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lease caching state bits.
    /// </summary>
    [Flags]
    public enum Smb2LeaseState : uint
    {
        /// <summary>
        /// No lease caching.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Read caching lease.
        /// </summary>
        ReadCaching = 0x00000001,

        /// <summary>
        /// Handle caching lease.
        /// </summary>
        HandleCaching = 0x00000002,

        /// <summary>
        /// Write caching lease.
        /// </summary>
        WriteCaching = 0x00000004
    }
}

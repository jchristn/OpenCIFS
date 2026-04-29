namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2/3 global capability flags.
    /// </summary>
    [Flags]
    public enum Smb2GlobalCapabilities : uint
    {
        /// <summary>
        /// No capabilities.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// DFS support.
        /// </summary>
        Dfs = 0x00000001,

        /// <summary>
        /// Leasing support.
        /// </summary>
        Leasing = 0x00000002,

        /// <summary>
        /// Large MTU support.
        /// </summary>
        LargeMtu = 0x00000004,

        /// <summary>
        /// Multichannel support.
        /// </summary>
        MultiChannel = 0x00000008,

        /// <summary>
        /// Persistent handles support.
        /// </summary>
        PersistentHandles = 0x00000010,

        /// <summary>
        /// Directory leasing support.
        /// </summary>
        DirectoryLeasing = 0x00000020,

        /// <summary>
        /// Encryption support.
        /// </summary>
        Encryption = 0x00000040
    }
}


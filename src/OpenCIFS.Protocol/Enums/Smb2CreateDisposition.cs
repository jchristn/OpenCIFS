namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 create dispositions.
    /// </summary>
    public enum Smb2CreateDisposition : uint
    {
        /// <summary>
        /// Supersede an existing file.
        /// </summary>
        Supersede = 0x00000000,

        /// <summary>
        /// Open an existing file.
        /// </summary>
        Open = 0x00000001,

        /// <summary>
        /// Create a new file.
        /// </summary>
        Create = 0x00000002,

        /// <summary>
        /// Open or create a file.
        /// </summary>
        OpenIf = 0x00000003,

        /// <summary>
        /// Overwrite an existing file.
        /// </summary>
        Overwrite = 0x00000004,

        /// <summary>
        /// Overwrite or create a file.
        /// </summary>
        OverwriteIf = 0x00000005
    }
}

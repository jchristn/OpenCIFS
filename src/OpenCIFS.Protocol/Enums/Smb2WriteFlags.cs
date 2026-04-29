namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 write flags.
    /// </summary>
    [Flags]
    public enum Smb2WriteFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Write-through.
        /// </summary>
        WriteThrough = 0x00000001,

        /// <summary>
        /// Unbuffered write.
        /// </summary>
        WriteUnbuffered = 0x00000002
    }
}

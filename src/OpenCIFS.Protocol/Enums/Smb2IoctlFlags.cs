namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 IOCTL request flags.
    /// </summary>
    [Flags]
    public enum Smb2IoctlFlags : uint
    {
        /// <summary>
        /// The request is an IOCTL operation.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// The request is an FSCTL operation.
        /// </summary>
        IsFsctl = 0x00000001
    }
}

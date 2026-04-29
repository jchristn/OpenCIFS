namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 close flags.
    /// </summary>
    [Flags]
    public enum Smb2CloseFlags : ushort
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// Return post-close attributes.
        /// </summary>
        PostQueryAttributes = 0x0001
    }
}

namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2/3 negotiate security-mode flags.
    /// </summary>
    [Flags]
    public enum Smb2SecurityMode : ushort
    {
        /// <summary>
        /// No flags are set.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// Message signing is supported.
        /// </summary>
        SigningEnabled = 0x0001,

        /// <summary>
        /// Message signing is required.
        /// </summary>
        SigningRequired = 0x0002
    }
}

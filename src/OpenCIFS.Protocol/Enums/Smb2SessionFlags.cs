namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2/3 session flags returned during session setup.
    /// </summary>
    [Flags]
    public enum Smb2SessionFlags : ushort
    {
        /// <summary>
        /// No flags are set.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// The authenticated session is a guest session.
        /// </summary>
        IsGuest = 0x0001,

        /// <summary>
        /// The authenticated session is a null session.
        /// </summary>
        IsNull = 0x0002,

        /// <summary>
        /// Encryption is required for the session.
        /// </summary>
        EncryptData = 0x0004
    }
}

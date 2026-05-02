namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 NEGOTIATE response security-mode flags.
    /// </summary>
    [Flags]
    public enum Smb1SecurityMode : byte
    {
        /// <summary>
        /// No security flags set.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Server uses user-level security (vs share-level).
        /// </summary>
        UserSecurity = 0x01,

        /// <summary>
        /// Server supports challenge/response (encrypted password) authentication.
        /// </summary>
        EncryptPasswords = 0x02,

        /// <summary>
        /// Server supports message signing.
        /// </summary>
        SigningEnabled = 0x04,

        /// <summary>
        /// Server requires message signing.
        /// </summary>
        SigningRequired = 0x08
    }
}

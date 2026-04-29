namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 create-request impersonation levels.
    /// </summary>
    public enum Smb2ImpersonationLevel : uint
    {
        /// <summary>
        /// Anonymous.
        /// </summary>
        Anonymous = 0x00000000,

        /// <summary>
        /// Identification.
        /// </summary>
        Identification = 0x00000001,

        /// <summary>
        /// Impersonation.
        /// </summary>
        Impersonation = 0x00000002,

        /// <summary>
        /// Delegate.
        /// </summary>
        Delegate = 0x00000003
    }
}

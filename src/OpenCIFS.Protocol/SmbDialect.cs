namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB and CIFS dialect identifiers planned for OpenCIFS.
    /// </summary>
    public enum SmbDialect
    {
        /// <summary>
        /// SMB 1.0 / CIFS compatibility mode.
        /// </summary>
        Cifs10 = 0,

        /// <summary>
        /// SMB 2.0.2.
        /// </summary>
        Smb2002 = 1,

        /// <summary>
        /// SMB 2.1.
        /// </summary>
        Smb21 = 2,

        /// <summary>
        /// SMB 3.0.
        /// </summary>
        Smb30 = 3,

        /// <summary>
        /// SMB 3.0.2.
        /// </summary>
        Smb302 = 4,

        /// <summary>
        /// SMB 3.1.1.
        /// </summary>
        Smb311 = 5
    }
}


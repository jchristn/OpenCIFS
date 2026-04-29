namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 info-type identifiers.
    /// </summary>
    public enum Smb2InfoType : byte
    {
        /// <summary>
        /// File information.
        /// </summary>
        File = 0x01,

        /// <summary>
        /// Filesystem information.
        /// </summary>
        FileSystem = 0x02,

        /// <summary>
        /// Security information.
        /// </summary>
        Security = 0x03,

        /// <summary>
        /// Quota information.
        /// </summary>
        Quota = 0x04
    }
}

namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2/3 share-type values returned by tree connect.
    /// </summary>
    public enum Smb2ShareType : byte
    {
        /// <summary>
        /// Unknown or unspecified share type.
        /// </summary>
        Unknown = 0x00,

        /// <summary>
        /// Disk-file share.
        /// </summary>
        Disk = 0x01,

        /// <summary>
        /// Named-pipe share.
        /// </summary>
        Pipe = 0x02,

        /// <summary>
        /// Printer share.
        /// </summary>
        Print = 0x03
    }
}

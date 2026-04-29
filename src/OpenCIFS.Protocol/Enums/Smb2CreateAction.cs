namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 create actions returned by the server.
    /// </summary>
    public enum Smb2CreateAction : uint
    {
        /// <summary>
        /// Existing file superseded.
        /// </summary>
        Superseded = 0x00000000,

        /// <summary>
        /// Existing file opened.
        /// </summary>
        Opened = 0x00000001,

        /// <summary>
        /// New file created.
        /// </summary>
        Created = 0x00000002,

        /// <summary>
        /// Existing file overwritten.
        /// </summary>
        Overwritten = 0x00000003
    }
}

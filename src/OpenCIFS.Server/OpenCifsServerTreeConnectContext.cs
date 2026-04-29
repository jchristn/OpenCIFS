namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Context passed to tree-connect callbacks before the tree is accepted.
    /// </summary>
    public sealed class OpenCifsServerTreeConnectContext
    {
        /// <summary>
        /// Session identifier from the SMB2 header.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Connected share name.
        /// </summary>
        public string ShareName { get; set; } = string.Empty;

        /// <summary>
        /// Resolved share root path.
        /// </summary>
        public string ShareRootPath { get; set; } = string.Empty;

        /// <summary>
        /// Parsed SMB2 tree-connect request body.
        /// </summary>
        public Smb2TreeConnectRequest Request { get; set; } = new Smb2TreeConnectRequest();
    }
}

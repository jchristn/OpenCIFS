namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Context passed to IOCTL callbacks before the fixed handler runs.
    /// </summary>
    public sealed class OpenCifsServerIoctlContext
    {
        /// <summary>
        /// Session identifier from the SMB2 header.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Tree identifier from the SMB2 header.
        /// </summary>
        public uint TreeId { get; set; }

        /// <summary>
        /// Share name when the request is open-scoped.
        /// </summary>
        public string? ShareName { get; set; }

        /// <summary>
        /// Backing filesystem path when the request is open-scoped.
        /// </summary>
        public string? FullPath { get; set; }

        /// <summary>
        /// Parsed SMB2 IOCTL request body.
        /// </summary>
        public Smb2IoctlRequest Request { get; set; } = new Smb2IoctlRequest();
    }
}

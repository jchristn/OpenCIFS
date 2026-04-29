namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Context passed to create callbacks before the fixed filesystem create path runs.
    /// </summary>
    public sealed class OpenCifsServerCreateContext
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
        /// Connected share name.
        /// </summary>
        public string ShareName { get; set; } = string.Empty;

        /// <summary>
        /// Resolved backing filesystem path.
        /// </summary>
        public string FullPath { get; set; } = string.Empty;

        /// <summary>
        /// Parsed SMB2 create request body.
        /// </summary>
        public Smb2CreateRequest Request { get; set; } = new Smb2CreateRequest();
    }
}

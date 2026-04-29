namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Context passed to set-info callbacks before the fixed metadata path runs.
    /// </summary>
    public sealed class OpenCifsServerSetInfoContext
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
        /// Parsed SMB2 set-info request body.
        /// </summary>
        public Smb2SetInfoRequest Request { get; set; } = new Smb2SetInfoRequest();
    }
}

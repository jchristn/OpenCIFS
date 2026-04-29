namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Header-wrapped SMB2 response emitted outside the synchronous request/response path.
    /// </summary>
    public sealed class OpenCifsServerAsyncResponse
    {
        /// <summary>
        /// Response header.
        /// </summary>
        public Smb2Header Header { get; set; } = null!;

        /// <summary>
        /// Response payload.
        /// </summary>
        public byte[] Payload { get; set; } = Array.Empty<byte>();
    }
}

namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Wraps an SMB2 tree-connect response with the server-assigned tree identifier.
    /// </summary>
    public sealed class OpenCifsServerTreeConnectResult
    {
        /// <summary>
        /// Response NTSTATUS.
        /// </summary>
        public NtStatus Status { get; set; } = NtStatus.Success;

        /// <summary>
        /// Server-assigned tree identifier.
        /// </summary>
        public uint TreeId { get; set; }

        /// <summary>
        /// Response body.
        /// </summary>
        public Smb2TreeConnectResponse Response
        {
            get
            {
                return _Response;
            }
            set
            {
                _Response = value ?? throw new ArgumentNullException(nameof(Response), "Response cannot be null.");
            }
        }

        private Smb2TreeConnectResponse _Response = new Smb2TreeConnectResponse();
    }
}

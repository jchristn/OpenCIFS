namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Wraps an SMB2 session-setup response with the server-assigned session identifier.
    /// </summary>
    public sealed class OpenCifsServerSessionSetupResult
    {
        /// <summary>
        /// Response NTSTATUS.
        /// </summary>
        public NtStatus Status { get; set; } = NtStatus.Success;

        /// <summary>
        /// Server-assigned session identifier.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Response body.
        /// </summary>
        public Smb2SessionSetupResponse Response
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

        private Smb2SessionSetupResponse _Response = new Smb2SessionSetupResponse();
    }
}

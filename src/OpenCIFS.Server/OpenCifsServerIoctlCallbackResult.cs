namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Optional callback override result for an SMB2 IOCTL request.
    /// </summary>
    public sealed class OpenCifsServerIoctlCallbackResult
    {
        /// <summary>
        /// NTSTATUS to return.
        /// </summary>
        public NtStatus Status { get; set; }

        /// <summary>
        /// IOCTL response body to return.
        /// </summary>
        public Smb2IoctlResponse Response { get; set; } = new Smb2IoctlResponse();
    }
}

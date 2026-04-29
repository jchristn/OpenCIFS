namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Result of processing an SMB2 cancel request against the current pending-request table.
    /// </summary>
    public sealed class OpenCifsServerCancelResult
    {
        /// <summary>
        /// Whether a pending request was found and cancelled.
        /// </summary>
        public bool WasCancelled { get; set; } = false;

        /// <summary>
        /// Target response header emitted when cancellation succeeds.
        /// </summary>
        public Smb2Header? TargetResponseHeader { get; set; }

        /// <summary>
        /// Target response payload emitted when cancellation succeeds.
        /// </summary>
        public byte[] TargetResponsePayload { get; set; } = Array.Empty<byte>();
    }
}

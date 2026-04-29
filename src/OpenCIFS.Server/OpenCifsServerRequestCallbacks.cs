namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Optional application-control callbacks for selected SMB2 request classes.
    /// </summary>
    public sealed class OpenCifsServerRequestCallbacks
    {
        /// <summary>
        /// Optional callback invoked after credentials verify but before the session is marked authenticated.
        /// Return <c>null</c> to continue, or an NTSTATUS to reject the session.
        /// </summary>
        public Func<OpenCifsServerAuthenticatedSessionContext, NtStatus?>? AuthenticatedSessionCallback { get; set; }

        /// <summary>
        /// Optional callback invoked before tree-connect succeeds.
        /// Return <c>null</c> to continue, or an NTSTATUS to reject the request.
        /// </summary>
        public Func<OpenCifsServerTreeConnectContext, NtStatus?>? TreeConnectCallback { get; set; }

        /// <summary>
        /// Optional callback invoked before create succeeds.
        /// Return <c>null</c> to continue, or an NTSTATUS to reject the request.
        /// </summary>
        public Func<OpenCifsServerCreateContext, NtStatus?>? CreateCallback { get; set; }

        /// <summary>
        /// Optional callback invoked before query-directory succeeds.
        /// Return <c>null</c> to continue, or an NTSTATUS to reject the request.
        /// </summary>
        public Func<OpenCifsServerQueryDirectoryContext, NtStatus?>? QueryDirectoryCallback { get; set; }

        /// <summary>
        /// Optional callback invoked before set-info succeeds.
        /// Return <c>null</c> to continue, or an NTSTATUS to reject the request.
        /// </summary>
        public Func<OpenCifsServerSetInfoContext, NtStatus?>? SetInfoCallback { get; set; }

        /// <summary>
        /// Optional callback invoked before the fixed IOCTL handler runs.
        /// Return <c>null</c> to continue, or a callback result to short-circuit the request.
        /// </summary>
        public Func<OpenCifsServerIoctlContext, OpenCifsServerIoctlCallbackResult?>? IoctlCallback { get; set; }
    }
}

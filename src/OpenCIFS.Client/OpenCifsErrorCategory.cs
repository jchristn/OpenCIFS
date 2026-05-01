namespace OpenCIFS.Client
{
    /// <summary>
    /// Normalized high-level error categories for managed OpenCIFS client failures.
    /// </summary>
    public enum OpenCifsErrorCategory
    {
        /// <summary>
        /// The failure does not map to a more specific normalized category.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// The target object or path was not found.
        /// </summary>
        NotFound,

        /// <summary>
        /// The caller was denied access.
        /// </summary>
        AccessDenied,

        /// <summary>
        /// The target object state conflicts with the requested operation.
        /// </summary>
        Conflict,

        /// <summary>
        /// The target capability or operation is not supported.
        /// </summary>
        Unsupported,

        /// <summary>
        /// The failure reflects an I/O-state problem on the target object or handle.
        /// </summary>
        IoError,

        /// <summary>
        /// The failure reflects a malformed, invalid, or otherwise protocol-level request or response state.
        /// </summary>
        ProtocolError,

        /// <summary>
        /// The operation was cancelled.
        /// </summary>
        Cancelled
    }
}

namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle flags used by SMB 3.x durable-handle v2 contexts.
    /// </summary>
    [Flags]
    public enum Smb2DurableHandleFlags : uint
    {
        /// <summary>
        /// No durable-handle flags are set.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// A persistent handle is requested or granted.
        /// </summary>
        Persistent = 0x00000002
    }
}

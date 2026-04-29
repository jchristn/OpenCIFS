namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2/3 header flags.
    /// </summary>
    [Flags]
    public enum Smb2HeaderFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Server to redirector response.
        /// </summary>
        ServerToRedir = 0x00000001,

        /// <summary>
        /// Asynchronous command.
        /// </summary>
        AsyncCommand = 0x00000002,

        /// <summary>
        /// Related compounded operation.
        /// </summary>
        RelatedOperations = 0x00000004,

        /// <summary>
        /// Signed message.
        /// </summary>
        Signed = 0x00000008,

        /// <summary>
        /// DFS operation.
        /// </summary>
        DfsOperations = 0x10000000,

        /// <summary>
        /// Replay operation.
        /// </summary>
        ReplayOperation = 0x20000000
    }
}

